use axum::{
    Extension, Json,
    extract::{Path, Query},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use std::sync::Arc;
use tracing::{error, info, warn};

use super::AuthorityStore;
use super::types::{Authority, AuthorityResponse};
use super::validation::{normalize_context, normalize_description, validate_context, validate_did, validate_name};
use crate::auth_manager::middleware::{AuthGuardOk, RbacGuard};
use crate::auth_manager::pat::{PatContext, PatResourceScope};
use crate::credential_providers::references::{ReferenceStores, ViewableKinds, all_visible, conflict_response};
use crate::tenancy::{
    PatTenantContext, ResourceKind, can_access, can_mutate, scope_allows_resource, tenant_for_create,
};
use crate::trust_registries::TrustRegistryListenerManager;

#[derive(Debug, Deserialize)]
pub struct CreateAuthorityRequest {
    #[serde(default)]
    pub tenant_id: Option<String>,
    pub name: String,

    /// External DID (required). Must start with `did:` and be unique across
    /// authorities.
    pub did: String,

    /// Optional description.
    #[serde(default)]
    pub description: Option<String>,

    /// Optional structured context. Must be a JSON object (or `null`).
    #[serde(default)]
    pub context: Option<serde_json::Value>,
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

#[derive(Debug, Deserialize)]
pub struct UpdateAuthorityRequest {
    pub name: String,

    /// External DID (required). Must be present in the payload but must
    /// match the stored DID — DID is immutable after creation. Callers may
    /// send the current DID as a no-op or omit any change.
    pub did: String,

    #[serde(default)]
    pub description: Option<String>,

    #[serde(default)]
    pub context: Option<serde_json::Value>,
}

/// List all authorities.
pub async fn list_authorities<S: AuthorityStore>(
    Extension(store): Extension<Arc<S>>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
) -> Result<Json<Vec<AuthorityResponse>>, (StatusCode, String)> {
    let mut authorities = store
        .list_all()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let context = tenant_context(&context);
    let scope = resource_scope(&scope);
    authorities.retain(|authority| {
        can_access(authority.tenant_id.as_deref(), context)
            && scope_allows_resource(scope, context, ResourceKind::Authorities, &authority.id)
    });
    Ok(Json(
        authorities
            .into_iter()
            .map(AuthorityResponse::from)
            .collect(),
    ))
}

/// Create an authority.
pub async fn create_authority<S: AuthorityStore>(
    Extension(store): Extension<Arc<S>>,
    pat: Option<Extension<PatContext>>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
    Json(mut req): Json<CreateAuthorityRequest>,
) -> Result<(StatusCode, Json<AuthorityResponse>), (StatusCode, String)> {
    req.tenant_id = tenant_for_create(req.tenant_id.take(), pat.is_some(), tenant_context(&context))
        .map_err(|message| (StatusCode::FORBIDDEN, message.to_string()))?;
    let name = validate_name(&req.name)?;
    let did = validate_did(&req.did)?;
    validate_context(&req.context)?;

    // Uniqueness — reject if any existing authority already uses this DID.
    if store
        .find_by_did(&did)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .is_some()
    {
        return Err((StatusCode::CONFLICT, "Authority DID already in use".to_string()));
    }

    let mut authority = Authority::new(
        uuid::Uuid::new_v4().to_string(),
        name,
        did,
        normalize_description(req.description),
        normalize_context(req.context),
    );
    authority.tenant_id = req.tenant_id;
    if !scope_allows_resource(
        resource_scope(&scope),
        tenant_context(&context),
        ResourceKind::Authorities,
        &authority.id,
    ) {
        return Err((StatusCode::FORBIDDEN, "Authority is outside this token's permitted scope".into()));
    }

    store
        .create(&authority)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    info!("Authority created: {} ({})", authority.name, authority.did);

    Ok((StatusCode::CREATED, Json(AuthorityResponse::from(authority))))
}

/// Get an authority by ID.
pub async fn get_authority<S: AuthorityStore>(
    Extension(store): Extension<Arc<S>>,
    Path(id): Path<String>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
) -> Result<Json<AuthorityResponse>, (StatusCode, String)> {
    let authority = store
        .get(&id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or((StatusCode::NOT_FOUND, "Authority not found".to_string()))?;
    if !can_access(authority.tenant_id.as_deref(), tenant_context(&context))
        || !scope_allows_resource(
            resource_scope(&scope),
            tenant_context(&context),
            ResourceKind::Authorities,
            &authority.id,
        )
    {
        return Err((StatusCode::NOT_FOUND, "Authority not found".to_string()));
    }
    Ok(Json(AuthorityResponse::from(authority)))
}

/// Update an authority. DID is immutable — the payload must echo the stored
/// DID or the request is rejected.
pub async fn update_authority<S: AuthorityStore>(
    Extension(store): Extension<Arc<S>>,
    Extension(tr_manager): Extension<Option<Arc<TrustRegistryListenerManager>>>,
    Path(id): Path<String>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
    Json(req): Json<UpdateAuthorityRequest>,
) -> Result<Json<AuthorityResponse>, (StatusCode, String)> {
    let name = validate_name(&req.name)?;
    let did = validate_did(&req.did)?;
    validate_context(&req.context)?;

    let mut authority = store
        .get(&id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or((StatusCode::NOT_FOUND, "Authority not found".to_string()))?;
    if !can_access(authority.tenant_id.as_deref(), tenant_context(&context))
        || !scope_allows_resource(
            resource_scope(&scope),
            tenant_context(&context),
            ResourceKind::Authorities,
            &authority.id,
        )
    {
        return Err((StatusCode::NOT_FOUND, "Authority not found".to_string()));
    }
    if !can_mutate(authority.tenant_id.as_deref(), tenant_context(&context)) {
        return Err((StatusCode::FORBIDDEN, "Authority is outside this token's permitted scope".into()));
    }

    if did != authority.did {
        return Err((StatusCode::BAD_REQUEST, "Authority DID is immutable and cannot be changed".to_string()));
    }

    authority.name = name;
    authority.description = normalize_description(req.description);
    authority.context = normalize_context(req.context);
    authority.updated_at = chrono::Utc::now();

    store
        .update(&authority)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    info!("Authority updated: {} ({})", authority.name, authority.id);
    if let (Some(manager), Some(issuer_store)) = (tr_manager, crate::gateways::connection_points::get_issuer_store()) {
        crate::trust_registries::reference_fields::spawn_authority_publish(manager, issuer_store, authority.clone());
    }
    Ok(Json(AuthorityResponse::from(authority)))
}

/// The refusal of a delete while Trust Checks or Trust Recorder entries use the Authority.
pub(crate) const AUTHORITY_IN_USE: &str = "The Authority is used by Trust Checks or Trust Recorder entries. Point \
                                           them at another Authority or remove them, then delete it";

/// The refusal of a forced delete while records the caller may not view use the Authority.
pub(crate) const AUTHORITY_IN_USE_OUT_OF_VIEW: &str = "The Authority is used by Trust Checks or Trust Recorder \
                                                       entries you cannot view, so it cannot be deleted with force";

#[derive(Debug, Default, Deserialize)]
pub struct DeleteAuthorityQuery {
    /// Delete even while Trust Checks or Trust Recorder entries the caller may view use the
    /// Authority. Those picked from the Authorities register then fail with
    /// `AUTHORITY_NOT_FOUND`, or write nothing, until they name another Authority.
    #[serde(default)]
    pub force: bool,
}

/// Delete an authority, unless a Trust Check or Trust Recorder entry names it: that is
/// refused with `409`, listing the surfaces and STS clients the caller may view with the
/// elements that name it and counting the rest, unless the caller sets `force` and may view
/// every one of them.
#[allow(clippy::too_many_arguments)]
pub async fn delete_authority<S: AuthorityStore>(
    Extension(store): Extension<Arc<S>>,
    Extension(references): Extension<ReferenceStores>,
    Extension(rbac): Extension<Option<RbacGuard>>,
    Path(id): Path<String>,
    Query(query): Query<DeleteAuthorityQuery>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
    caller: Option<Extension<AuthGuardOk>>,
    pat: Option<Extension<PatContext>>,
) -> Response {
    let authority = match store.get(&id).await {
        Ok(Some(authority)) => authority,
        Ok(None) => return not_found(),
        Err(e) => return internal_error("load", &id, e),
    };
    if !can_access(authority.tenant_id.as_deref(), tenant_context(&context))
        || !scope_allows_resource(
            resource_scope(&scope),
            tenant_context(&context),
            ResourceKind::Authorities,
            &authority.id,
        )
    {
        return not_found();
    }
    if !can_mutate(authority.tenant_id.as_deref(), tenant_context(&context)) {
        return (StatusCode::FORBIDDEN, "Authority is outside this token's permitted scope").into_response();
    }

    let _bindings = crate::identity::handlers::surface_grants::hold_provider_bindings_exclusively().await;
    let referrers = match references
        .referrers_of_authority(&authority.did)
        .await
    {
        Ok(referrers) => referrers,
        Err(e) => return internal_error("find the records using", &id, e),
    };
    if !referrers.is_empty() {
        let viewable = ViewableKinds::of_caller(
            rbac.as_ref(),
            caller
                .as_ref()
                .map(|Extension(caller)| caller),
            pat.as_ref()
                .map(|Extension(pat)| pat),
        )
        .await;
        let refusal = match query.force {
            false => Some(AUTHORITY_IN_USE),
            true if !all_visible(&referrers, &viewable, tenant_context(&context), resource_scope(&scope)) => {
                Some(AUTHORITY_IN_USE_OUT_OF_VIEW)
            }
            true => None,
        };
        if let Some(message) = refusal {
            return conflict_response(message, &referrers, &viewable, tenant_context(&context), resource_scope(&scope));
        }
    }

    if let Err(e) = store.delete(&id).await {
        return internal_error("delete", &id, e);
    }
    if query.force {
        if !referrers.is_empty() {
            let referrer_ids: Vec<&str> = referrers
                .iter()
                .map(|referrer| referrer.id.as_str())
                .collect();
            warn!(
                authority_id = %authority.id,
                did = %authority.did,
                referrers = ?referrer_ids,
                "Authority deleted with force while Trust Checks or Trust Recorder entries still use it"
            );
        }
        crate::audit::authority_force_deletes::authority_force_deleted(&authority, &referrers);
    }

    info!("Authority deleted: {} ({})", authority.name, authority.id);
    StatusCode::NO_CONTENT.into_response()
}

fn not_found() -> Response {
    (StatusCode::NOT_FOUND, "Authority not found").into_response()
}

fn internal_error(
    action: &str,
    id: &str,
    error: impl std::fmt::Display,
) -> Response {
    error!(authority_id = %id, %error, "Failed to {action} the Authority");
    (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error").into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authorities::filesystem::FileSystemAuthorityStore;
    use axum::http::StatusCode;
    use serde_json::json;
    use tempfile::TempDir;

    async fn test_store() -> (Arc<FileSystemAuthorityStore>, TempDir) {
        let dir = TempDir::new().unwrap();
        let store = FileSystemAuthorityStore::new(dir.path().to_path_buf())
            .await
            .unwrap();
        (Arc::new(store), dir)
    }

    #[tokio::test]
    async fn list_empty_returns_empty_vec() {
        let (store, _dir) = test_store().await;
        let Json(body) = list_authorities(Extension(store), None, None)
            .await
            .unwrap();
        assert!(body.is_empty());
    }

    #[tokio::test]
    async fn create_then_get_round_trips_all_fields() {
        let (store, _dir) = test_store().await;
        let (status, Json(created)) = create_authority(
            Extension(store.clone()),
            None,
            None,
            None,
            Json(CreateAuthorityRequest {
                tenant_id: None,
                name: "Acme".to_string(),
                did: "did:web:acme.example.com".to_string(),
                description: Some("Anchor".to_string()),
                context: Some(json!({ "role": "issuer", "sla": 99 })),
            }),
        )
        .await
        .unwrap();
        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(created.name, "Acme");
        assert_eq!(created.did, "did:web:acme.example.com");
        assert_eq!(created.description.as_deref(), Some("Anchor"));
        assert_eq!(
            created
                .context
                .as_ref()
                .and_then(|v| v.get("role"))
                .and_then(|v| v.as_str()),
            Some("issuer")
        );

        let Json(fetched) = get_authority(Extension(store), Path(created.id.clone()), None, None)
            .await
            .unwrap();
        assert_eq!(fetched.did, created.did);
        assert_eq!(fetched.context, created.context);
    }

    #[tokio::test]
    async fn create_rejects_blank_name() {
        let (store, _dir) = test_store().await;
        let err = create_authority(
            Extension(store),
            None,
            None,
            None,
            Json(CreateAuthorityRequest {
                tenant_id: None,
                name: "   ".to_string(),
                did: "did:web:acme.example.com".to_string(),
                description: None,
                context: None,
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
        assert_eq!(err.1, "Authority name cannot be empty");
    }

    #[tokio::test]
    async fn create_rejects_blank_did() {
        let (store, _dir) = test_store().await;
        let err = create_authority(
            Extension(store),
            None,
            None,
            None,
            Json(CreateAuthorityRequest {
                tenant_id: None,
                name: "Acme".to_string(),
                did: "".to_string(),
                description: None,
                context: None,
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
        assert_eq!(err.1, "Authority DID cannot be empty");
    }

    #[tokio::test]
    async fn create_rejects_did_missing_prefix() {
        let (store, _dir) = test_store().await;
        let err = create_authority(
            Extension(store),
            None,
            None,
            None,
            Json(CreateAuthorityRequest {
                tenant_id: None,
                name: "Acme".to_string(),
                did: "acme".to_string(),
                description: None,
                context: None,
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
        assert_eq!(err.1, "Authority DID must start with 'did:'");
    }

    #[tokio::test]
    async fn create_rejects_non_object_context() {
        let (store, _dir) = test_store().await;
        let err = create_authority(
            Extension(store),
            None,
            None,
            None,
            Json(CreateAuthorityRequest {
                tenant_id: None,
                name: "Acme".to_string(),
                did: "did:web:acme.example.com".to_string(),
                description: None,
                context: Some(json!("hello")),
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
        assert_eq!(err.1, "Authority context must be a JSON object");
    }

    #[tokio::test]
    async fn create_accepts_null_context() {
        let (store, _dir) = test_store().await;
        let (_, Json(created)) = create_authority(
            Extension(store),
            None,
            None,
            None,
            Json(CreateAuthorityRequest {
                tenant_id: None,
                name: "Acme".to_string(),
                did: "did:web:acme.example.com".to_string(),
                description: None,
                context: Some(serde_json::Value::Null),
            }),
        )
        .await
        .unwrap();
        assert!(created.context.is_none());
    }

    #[tokio::test]
    async fn create_rejects_duplicate_did() {
        let (store, _dir) = test_store().await;
        let _ = create_authority(
            Extension(store.clone()),
            None,
            None,
            None,
            Json(CreateAuthorityRequest {
                tenant_id: None,
                name: "Acme".to_string(),
                did: "did:web:acme.example.com".to_string(),
                description: None,
                context: None,
            }),
        )
        .await
        .unwrap();

        let err = create_authority(
            Extension(store),
            None,
            None,
            None,
            Json(CreateAuthorityRequest {
                tenant_id: None,
                name: "Acme 2".to_string(),
                did: "did:web:acme.example.com".to_string(),
                description: None,
                context: None,
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(err.0, StatusCode::CONFLICT);
        assert_eq!(err.1, "Authority DID already in use");
    }

    #[tokio::test]
    async fn update_rejects_did_change() {
        let (store, _dir) = test_store().await;
        let (_, Json(created)) = create_authority(
            Extension(store.clone()),
            None,
            None,
            None,
            Json(CreateAuthorityRequest {
                tenant_id: None,
                name: "Acme".to_string(),
                did: "did:web:acme.example.com".to_string(),
                description: None,
                context: None,
            }),
        )
        .await
        .unwrap();

        let err = update_authority(
            Extension(store),
            Extension(None),
            Path(created.id.clone()),
            None,
            None,
            Json(UpdateAuthorityRequest {
                name: "Acme".to_string(),
                did: "did:web:evil.example.com".to_string(),
                description: None,
                context: None,
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
        assert_eq!(err.1, "Authority DID is immutable and cannot be changed");
    }

    #[tokio::test]
    async fn update_rejects_blank_name() {
        let (store, _dir) = test_store().await;
        let (_, Json(created)) = create_authority(
            Extension(store.clone()),
            None,
            None,
            None,
            Json(CreateAuthorityRequest {
                tenant_id: None,
                name: "Acme".to_string(),
                did: "did:web:acme.example.com".to_string(),
                description: None,
                context: None,
            }),
        )
        .await
        .unwrap();

        let err = update_authority(
            Extension(store),
            Extension(None),
            Path(created.id.clone()),
            None,
            None,
            Json(UpdateAuthorityRequest {
                name: "  ".to_string(),
                did: created.did.clone(),
                description: None,
                context: None,
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
        assert_eq!(err.1, "Authority name cannot be empty");
    }

    #[tokio::test]
    async fn update_mutates_updated_at_and_context() {
        let (store, _dir) = test_store().await;
        let (_, Json(created)) = create_authority(
            Extension(store.clone()),
            None,
            None,
            None,
            Json(CreateAuthorityRequest {
                tenant_id: None,
                name: "Acme".to_string(),
                did: "did:web:acme.example.com".to_string(),
                description: None,
                context: None,
            }),
        )
        .await
        .unwrap();

        // Ensure updated_at can differ from created_at by more than a nanosecond.
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;

        let Json(updated) = update_authority(
            Extension(store),
            Extension(None),
            Path(created.id.clone()),
            None,
            None,
            Json(UpdateAuthorityRequest {
                name: "Acme (renamed)".to_string(),
                did: created.did.clone(),
                description: Some("Renamed".to_string()),
                context: Some(json!({ "role": "authority" })),
            }),
        )
        .await
        .unwrap();
        assert_eq!(updated.name, "Acme (renamed)");
        assert_eq!(updated.description.as_deref(), Some("Renamed"));
        assert!(updated.updated_at > created.updated_at);
        assert_eq!(
            updated
                .context
                .as_ref()
                .and_then(|v| v.get("role"))
                .and_then(|v| v.as_str()),
            Some("authority")
        );
    }

    #[tokio::test]
    async fn delete_removes_record() {
        let (store, _dir) = test_store().await;
        let (_, Json(created)) = create_authority(
            Extension(store.clone()),
            None,
            None,
            None,
            Json(CreateAuthorityRequest {
                tenant_id: None,
                name: "Acme".to_string(),
                did: "did:web:acme.example.com".to_string(),
                description: None,
                context: None,
            }),
        )
        .await
        .unwrap();

        let status = delete(&store, ReferenceStores::default(), &created.id, None, false)
            .await
            .status();
        assert_eq!(status, StatusCode::NO_CONTENT);

        let err = get_authority(Extension(store), Path(created.id), None, None)
            .await
            .unwrap_err();
        assert_eq!(err.0, StatusCode::NOT_FOUND);
    }

    async fn delete(
        store: &Arc<FileSystemAuthorityStore>,
        references: ReferenceStores,
        id: &str,
        context: Option<Extension<PatTenantContext>>,
        force: bool,
    ) -> Response {
        delete_as(None, store, references, id, context, force).await
    }

    async fn delete_as(
        viewer: Option<&crate::credential_providers::references::test_support::Administrator>,
        store: &Arc<FileSystemAuthorityStore>,
        references: ReferenceStores,
        id: &str,
        context: Option<Extension<PatTenantContext>>,
        force: bool,
    ) -> Response {
        delete_authority(
            Extension(store.clone()),
            Extension(references),
            Extension(viewer.map(|viewer| viewer.rbac.clone())),
            Path(id.to_string()),
            Query(DeleteAuthorityQuery { force }),
            context,
            None,
            viewer.map(|viewer| Extension(viewer.caller.clone())),
            None,
        )
        .await
    }

    async fn create_for_tenant(
        store: &Arc<FileSystemAuthorityStore>,
        tenant_id: Option<&str>,
        did: &str,
    ) -> AuthorityResponse {
        let (_, Json(created)) = create_authority(
            Extension(store.clone()),
            None,
            None,
            None,
            Json(CreateAuthorityRequest {
                tenant_id: tenant_id.map(str::to_string),
                name: "Operator anchor".to_string(),
                did: did.to_string(),
                description: None,
                context: None,
            }),
        )
        .await
        .unwrap();
        created
    }

    fn tenant_a() -> Option<Extension<PatTenantContext>> {
        Some(Extension(PatTenantContext {
            token_id: "token-a".into(),
            tenant_id: "tenant-a".into(),
        }))
    }

    fn rename(did: &str) -> Json<UpdateAuthorityRequest> {
        Json(UpdateAuthorityRequest {
            name: "Tenant anchor".to_string(),
            did: did.to_string(),
            description: None,
            context: None,
        })
    }

    #[tokio::test]
    async fn a_tenant_token_cannot_update_or_delete_an_appliance_wide_authority() {
        let (store, _dir) = test_store().await;
        let created = create_for_tenant(&store, None, "did:web:operator.example.com").await;

        let Json(read) = get_authority(Extension(store.clone()), Path(created.id.clone()), tenant_a(), None)
            .await
            .unwrap();
        assert_eq!(read.did, "did:web:operator.example.com");

        let update = update_authority(
            Extension(store.clone()),
            Extension(None),
            Path(created.id.clone()),
            tenant_a(),
            None,
            rename(&created.did),
        )
        .await;
        assert_eq!(
            update
                .err()
                .map(|(status, _)| status),
            Some(StatusCode::FORBIDDEN)
        );

        let delete = delete(&store, ReferenceStores::default(), &created.id, tenant_a(), false).await;
        assert_eq!(delete.status(), StatusCode::FORBIDDEN);

        let Json(after) = get_authority(Extension(store), Path(created.id), None, None)
            .await
            .unwrap();
        assert_eq!(after.name, "Operator anchor");
        assert_eq!(after.updated_at, created.updated_at);
    }

    #[tokio::test]
    async fn another_tenants_authority_is_not_found_on_update_or_delete() {
        let (store, _dir) = test_store().await;
        let created = create_for_tenant(&store, Some("tenant-b"), "did:web:operator.example.com").await;

        let update = update_authority(
            Extension(store.clone()),
            Extension(None),
            Path(created.id.clone()),
            tenant_a(),
            None,
            rename(&created.did),
        )
        .await;
        assert_eq!(
            update
                .err()
                .map(|(status, _)| status),
            Some(StatusCode::NOT_FOUND)
        );

        let delete = delete(&store, ReferenceStores::default(), &created.id, tenant_a(), false).await;
        assert_eq!(delete.status(), StatusCode::NOT_FOUND);

        let Json(after) = get_authority(Extension(store), Path(created.id), None, None)
            .await
            .unwrap();
        assert_eq!(after.name, "Operator anchor");
        assert_eq!(after.updated_at, created.updated_at);
    }

    #[tokio::test]
    async fn a_tenant_token_can_update_and_delete_its_own_authority() {
        let (store, _dir) = test_store().await;
        let created = create_for_tenant(&store, Some("tenant-a"), "did:web:tenant.example.com").await;

        let Json(updated) = update_authority(
            Extension(store.clone()),
            Extension(None),
            Path(created.id.clone()),
            tenant_a(),
            None,
            rename(&created.did),
        )
        .await
        .unwrap();
        assert_eq!(updated.name, "Tenant anchor");

        let status = delete(&store, ReferenceStores::default(), &created.id, tenant_a(), false)
            .await
            .status();
        assert_eq!(status, StatusCode::NO_CONTENT);
    }

    async fn surfaces_using(
        did: &str,
        dir: &std::path::Path,
    ) -> ReferenceStores {
        use crate::surfaces::AgentSurfaceStore;

        let surfaces = Arc::new(
            crate::surfaces::FileSystemAgentSurfaceStore::new(dir.join("surfaces"))
                .await
                .unwrap(),
        );
        let surface: crate::config::agent_surface::AgentSurface = serde_json::from_value(json!({
            "surface_id": "orders", "name": "Orders",
            "access_point": {
                "listen_address": "0.0.0.0:8443", "route": "/orders", "protocol": "a2a",
                "trust_check_list": [{
                    "id": "acme-check", "trust_registry_id": "tr-1", "query_type": "recognition",
                    "authority_source": "authority",
                    "query": {"authority_id": did, "entity_id": "{{ input.agent.did }}"}
                }]
            },
            "target": {"endpoint": "https://api.example.com"}
        }))
        .unwrap();
        surfaces
            .save(&surface)
            .await
            .unwrap();
        ReferenceStores {
            surfaces: Some(surfaces),
            ..Default::default()
        }
    }

    async fn body(response: Response) -> serde_json::Value {
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    #[tokio::test]
    async fn deleting_an_authority_a_trust_check_uses_is_refused_and_keeps_it() {
        let (store, _dir) = test_store().await;
        let created = create_for_tenant(&store, None, "did:web:acme.example.com").await;
        let references_dir = TempDir::new().unwrap();
        let references = surfaces_using(&created.did, references_dir.path()).await;

        let refusal = delete(&store, references, &created.id, None, false).await;

        assert_eq!(refusal.status(), StatusCode::CONFLICT);
        let refusal = body(refusal).await;
        assert_eq!(refusal["message"], AUTHORITY_IN_USE);
        assert_eq!(refusal["references"], json!([]), "a caller with no view permission is named nothing");
        assert_eq!(refusal["hidden_references"], 1);
        assert!(
            get_authority(Extension(store), Path(created.id), None, None)
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn an_administrator_is_shown_the_surface_and_trust_check_using_the_authority() {
        let (store, _dir) = test_store().await;
        let created = create_for_tenant(&store, None, "did:web:acme.example.com").await;
        let references_dir = TempDir::new().unwrap();
        let references = surfaces_using(&created.did, references_dir.path()).await;
        let admin = crate::credential_providers::references::test_support::administrator().await;

        let refusal = delete_as(Some(&admin), &store, references, &created.id, None, false).await;

        assert_eq!(refusal.status(), StatusCode::CONFLICT);
        assert_eq!(
            body(refusal).await["references"],
            json!([{"kind": "surface", "id": "orders", "name": "Orders", "uses": [
                {"element": "trust_check", "id": "acme-check", "placement": "access_point"}
            ]}])
        );
    }

    #[tokio::test]
    async fn an_authority_in_use_is_deleted_with_force_and_the_delete_is_recorded() {
        let (store, _dir) = test_store().await;
        let created = create_for_tenant(&store, None, "did:web:acme.example.com").await;
        let references_dir = TempDir::new().unwrap();
        let references = surfaces_using(&created.did, references_dir.path()).await;

        let admin = crate::credential_providers::references::test_support::administrator().await;

        let (status, records) = crate::audit::producer::capture(crate::audit::context::in_management_request(
            crate::audit::events::Actor::user("u-1"),
            delete_as(Some(&admin), &store, references, &created.id, None, true),
        ))
        .await;

        assert_eq!(status.status(), StatusCode::NO_CONTENT);
        assert!(
            get_authority(Extension(store), Path(created.id.clone()), None, None)
                .await
                .is_err()
        );
        assert_eq!(records.len(), 1, "{records:?}");
        assert_eq!(crate::delegation_vault::audit::action_category(&records[0].event), "authority_force_deleted");
        assert_eq!(
            serde_json::to_value(&records[0]).unwrap()["event"]["authority_force_deleted"],
            json!({
                "actor": {"kind": "user", "id": "u-1"},
                "authority_id": created.id,
                "did": "did:web:acme.example.com",
                "force": true,
                "referrers": [{"kind": "surface", "id": "orders"}],
            })
        );
    }

    #[tokio::test]
    async fn a_forced_delete_is_refused_while_a_user_of_the_authority_is_hidden_from_the_caller() {
        let (store, _dir) = test_store().await;
        let created = create_for_tenant(&store, None, "did:web:acme.example.com").await;
        let references_dir = TempDir::new().unwrap();
        let references = surfaces_using(&created.did, references_dir.path()).await;

        let (refusal, records) = crate::audit::producer::capture(crate::audit::context::in_management_request(
            crate::audit::events::Actor::user("u-1"),
            delete(&store, references, &created.id, None, true),
        ))
        .await;

        assert_eq!(refusal.status(), StatusCode::CONFLICT);
        let refusal = body(refusal).await;
        assert_eq!(refusal["message"], AUTHORITY_IN_USE_OUT_OF_VIEW);
        assert_eq!(refusal["hidden_references"], 1);
        assert!(records.is_empty(), "{records:?}");
        assert!(
            get_authority(Extension(store), Path(created.id), None, None)
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn an_authority_nothing_uses_is_deleted_without_an_audit_record() {
        let (store, _dir) = test_store().await;
        let created = create_for_tenant(&store, None, "did:web:acme.example.com").await;
        let references_dir = TempDir::new().unwrap();
        let references = surfaces_using("did:web:other.example.com", references_dir.path()).await;

        let (status, records) = crate::audit::producer::capture(crate::audit::context::in_management_request(
            crate::audit::events::Actor::user("u-1"),
            delete(&store, references, &created.id, None, false),
        ))
        .await;

        assert_eq!(status.status(), StatusCode::NO_CONTENT);
        assert!(records.is_empty(), "{records:?}");
    }
}
