use axum::{Extension, Json, extract::Path, http::StatusCode};
use serde::Deserialize;
use std::sync::Arc;
use tracing::info;

use super::AuthorityStore;
use super::types::{Authority, AuthorityResponse};
use super::validation::{normalize_context, normalize_description, validate_context, validate_did, validate_name};
use crate::auth_manager::pat::{PatContext, PatResourceScope};
use crate::tenancy::{PatTenantContext, ResourceKind, can_access, scope_allows_resource, tenant_for_create};
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

/// Delete an authority.
pub async fn delete_authority<S: AuthorityStore>(
    Extension(store): Extension<Arc<S>>,
    Path(id): Path<String>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
) -> Result<StatusCode, (StatusCode, String)> {
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
        return Err((StatusCode::FORBIDDEN, "Authority is outside this token's permitted scope".into()));
    }

    store
        .delete(&id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    info!("Authority deleted: {} ({})", authority.name, authority.id);
    Ok(StatusCode::NO_CONTENT)
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

        let status = delete_authority(Extension(store.clone()), Path(created.id.clone()), None, None)
            .await
            .unwrap();
        assert_eq!(status, StatusCode::NO_CONTENT);

        let err = get_authority(Extension(store), Path(created.id), None, None)
            .await
            .unwrap_err();
        assert_eq!(err.0, StatusCode::NOT_FOUND);
    }
}
