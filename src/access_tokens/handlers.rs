use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::{Extension, Json};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::info;

use crate::auth_manager::middleware::AuthGuardOk;
use crate::auth_manager::pat::{PatContext, PatDelegationContext};
use crate::auth_manager::resource_scope::{self, RequiredHeader};
use crate::rbac::RbacConfig;

use super::store::{FsAccessTokenStore, hash_secret};
use super::{AccessToken, AccessTokenMeta, MAX_DELEGATION_DEPTH, generate_token};

const MAX_EXPIRY_DAYS: u32 = 3650;

fn normalize_pattern(pattern: Option<String>) -> Option<String> {
    pattern
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

/// Validate the resource scope and enforce the exact-selector requirement:
/// a broad (multi-valued) tenant selector is rejected at issue time unless a
/// trusted, edge-authenticated proxy owns the tenant header
/// (`tenancy.trusted_tenant_header`). Fails closed when no such edge is set.
fn validate_scope_and_tenant_selector(
    pattern: Option<&str>,
    headers: &[RequiredHeader],
    tenancy: Option<&crate::tenancy::TenancyConfig>,
) -> Result<(), (StatusCode, String)> {
    let compiled = resource_scope::compile(pattern, headers).map_err(|error| (StatusCode::BAD_REQUEST, error))?;
    if let Some(selector) = compiled.tenant_selector() {
        let trusted_edge = tenancy.and_then(|config| {
            config
                .trusted_tenant_header
                .as_ref()
        });
        if !crate::tenancy::header_derived_tenant_permitted(selector, trusted_edge) {
            return Err((
                StatusCode::BAD_REQUEST,
                format!(
                    "tenant selector for header '{}' is broad (admits more than one value); a \
                     single-tenant token must use an exact-literal header pattern (e.g. \
                     `123456789012`), or the deployment must configure \
                     `tenancy.trusted_tenant_header` for an edge-authenticated proxy that strips \
                     this header",
                    selector.header_name
                ),
            ));
        }
    }
    Ok(())
}

fn validate_delegated_scopes(
    parent_scopes: Option<&[String]>,
    requested_scopes: &[String],
) -> Result<(), &'static str> {
    if let Some(parent_scopes) = parent_scopes
        && (requested_scopes.is_empty()
            || requested_scopes
                .iter()
                .any(|scope| !parent_scopes.contains(scope)))
    {
        return Err("a scoped access token may create only a non-empty subset of its own scopes");
    }
    Ok(())
}

fn delegated_lineage(parent: Option<&PatDelegationContext>) -> Result<(Option<String>, u32), &'static str> {
    let Some(parent) = parent else {
        return Ok((None, 0));
    };
    validate_delegation_authority(Some(parent))?;
    let depth = parent
        .delegation_depth
        .checked_add(1)
        .ok_or("access-token delegation depth is invalid")?;
    if depth > MAX_DELEGATION_DEPTH {
        return Err("access-token delegation depth exceeds the configured maximum");
    }
    Ok((Some(parent.token_id.clone()), depth))
}

fn validate_delegation_authority(parent: Option<&PatDelegationContext>) -> Result<(), &'static str> {
    if parent.is_some_and(|parent| parent.resource_scoped) {
        return Err("a resource-scoped access token cannot delegate or modify access tokens");
    }
    Ok(())
}

fn validate_target_authority(
    store: &FsAccessTokenStore,
    caller: Option<&PatDelegationContext>,
    target_id: &str,
) -> Result<(), (StatusCode, String)> {
    let Some(caller) = caller else {
        return Ok(());
    };
    validate_delegation_authority(Some(caller)).map_err(|message| (StatusCode::FORBIDDEN, message.into()))?;
    store
        .controls(&caller.token_id, target_id)
        .then_some(())
        .ok_or((StatusCode::FORBIDDEN, "an access token may manage only itself or its descendants".into()))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateAccessTokenRequest {
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub scopes: Vec<String>,
    #[serde(default)]
    pub resource_pattern: Option<String>,
    #[serde(default)]
    pub required_headers: Vec<RequiredHeader>,
    #[serde(default)]
    pub expires_at: Option<DateTime<Utc>>,
}

fn resolve_expiry(
    now: DateTime<Utc>,
    expires_at: Option<DateTime<Utc>>,
) -> Result<Option<DateTime<Utc>>, String> {
    match expires_at {
        Some(expiry) if expiry <= now => Err("expires_at must be in the future".into()),
        Some(expiry) if expiry > now + Duration::days(i64::from(MAX_EXPIRY_DAYS)) => {
            Err(format!("expires_at must be within {MAX_EXPIRY_DAYS} days"))
        }
        Some(expiry) => Ok(Some(expiry)),
        None => Ok(None),
    }
}

#[derive(Serialize)]
pub struct CreateAccessTokenResponse {
    pub token: String,
    #[serde(flatten)]
    pub meta: AccessTokenMeta,
}

pub async fn list_access_tokens(
    State(store): State<Arc<FsAccessTokenStore>>,
    delegation: Option<Extension<PatDelegationContext>>,
) -> Json<serde_json::Value> {
    let now = Utc::now();
    let mut items: Vec<_> = store
        .list()
        .iter()
        .filter(|token| {
            delegation
                .as_ref()
                .is_none_or(|Extension(context)| store.controls(&context.token_id, &token.id))
        })
        .map(|token| AccessTokenMeta::from_token(token, now))
        .collect();
    items.sort_by(|left, right| {
        right
            .created_at
            .cmp(&left.created_at)
    });
    Json(json!({ "access_tokens": items }))
}

pub async fn create_access_token(
    State(store): State<Arc<FsAccessTokenStore>>,
    Extension(rbac): Extension<Arc<RbacConfig>>,
    caller: Option<Extension<AuthGuardOk>>,
    pat: Option<Extension<PatContext>>,
    delegation: Option<Extension<PatDelegationContext>>,
    tenancy: Option<Extension<Arc<crate::tenancy::TenancyConfig>>>,
    Json(request): Json<CreateAccessTokenRequest>,
) -> Result<(StatusCode, Json<CreateAccessTokenResponse>), (StatusCode, String)> {
    let name = request.name.trim();
    if name.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "name is required".into()));
    }
    for scope in &request.scopes {
        if !rbac
            .permissions
            .contains_key(scope)
        {
            return Err((StatusCode::BAD_REQUEST, format!("unknown scope: {scope}")));
        }
    }
    let parent_scopes = pat
        .as_ref()
        .and_then(|Extension(PatContext(scopes))| scopes.as_deref());
    validate_delegated_scopes(parent_scopes, &request.scopes)
        .map_err(|message| (StatusCode::FORBIDDEN, message.into()))?;
    let (parent_token_id, delegation_depth) = delegated_lineage(
        delegation
            .as_ref()
            .map(|Extension(context)| context),
    )
    .map_err(|message| (StatusCode::FORBIDDEN, message.into()))?;
    validate_scope_and_tenant_selector(
        request
            .resource_pattern
            .as_deref(),
        &request.required_headers,
        tenancy
            .as_ref()
            .map(|Extension(config)| config.as_ref()),
    )?;
    let caller_id = caller
        .map(|Extension(auth)| auth.0)
        .unwrap_or_default();
    if caller_id.is_empty() {
        return Err((StatusCode::UNAUTHORIZED, "no authenticated caller".into()));
    }

    let (id, secret) = generate_token();
    let now = Utc::now();
    let expires_at = resolve_expiry(now, request.expires_at).map_err(|error| (StatusCode::BAD_REQUEST, error))?;
    let token = AccessToken {
        id,
        name: name.into(),
        description: request.description,
        token_hash: hash_secret(&secret),
        user_id: caller_id.clone(),
        scopes: request.scopes,
        resource_pattern: normalize_pattern(request.resource_pattern),
        required_headers: request.required_headers,
        created_by: caller_id,
        parent_token_id,
        delegation_depth,
        created_at: now,
        last_used_at: None,
        expires_at,
        revoked_at: None,
    };
    store
        .create(token.clone())
        .await
        .map_err(|error| {
            if error.kind() == std::io::ErrorKind::PermissionDenied {
                (StatusCode::FORBIDDEN, "parent access token is no longer active".to_string())
            } else {
                (StatusCode::INTERNAL_SERVER_ERROR, format!("failed to store token: {error}"))
            }
        })?;
    info!(token_id = %token.id, user_id = %token.user_id, "Created management access token");

    Ok((
        StatusCode::CREATED,
        Json(CreateAccessTokenResponse {
            token: secret,
            meta: AccessTokenMeta::from_token(&token, now),
        }),
    ))
}

pub async fn get_access_token(
    State(store): State<Arc<FsAccessTokenStore>>,
    Path(id): Path<String>,
    delegation: Option<Extension<PatDelegationContext>>,
) -> Result<Json<AccessTokenMeta>, (StatusCode, String)> {
    if delegation
        .as_ref()
        .is_some_and(|Extension(context)| !store.controls(&context.token_id, &id))
    {
        return Err((StatusCode::NOT_FOUND, "access token not found".into()));
    }
    store
        .get(&id)
        .map(|token| Json(AccessTokenMeta::from_token(&token, Utc::now())))
        .ok_or((StatusCode::NOT_FOUND, "access token not found".into()))
}

#[derive(Deserialize)]
pub struct UpdateAccessTokenRequest {
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub scopes: Vec<String>,
    #[serde(default)]
    pub resource_pattern: Option<String>,
    #[serde(default)]
    pub required_headers: Vec<RequiredHeader>,
}

pub async fn update_access_token(
    State(store): State<Arc<FsAccessTokenStore>>,
    Extension(rbac): Extension<Arc<RbacConfig>>,
    Path(id): Path<String>,
    pat: Option<Extension<PatContext>>,
    delegation: Option<Extension<PatDelegationContext>>,
    tenancy: Option<Extension<Arc<crate::tenancy::TenancyConfig>>>,
    Json(request): Json<UpdateAccessTokenRequest>,
) -> Result<Json<AccessTokenMeta>, (StatusCode, String)> {
    let name = request.name.trim();
    if name.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "name is required".into()));
    }
    for scope in &request.scopes {
        if !rbac
            .permissions
            .contains_key(scope)
        {
            return Err((StatusCode::BAD_REQUEST, format!("unknown scope: {scope}")));
        }
    }
    let parent_scopes = pat
        .as_ref()
        .and_then(|Extension(PatContext(scopes))| scopes.as_deref());
    validate_target_authority(
        &store,
        delegation
            .as_ref()
            .map(|Extension(context)| context),
        &id,
    )?;
    validate_delegated_scopes(parent_scopes, &request.scopes)
        .map_err(|message| (StatusCode::FORBIDDEN, message.into()))?;
    validate_scope_and_tenant_selector(
        request
            .resource_pattern
            .as_deref(),
        &request.required_headers,
        tenancy
            .as_ref()
            .map(|Extension(config)| config.as_ref()),
    )?;
    if store
        .get(&id)
        .is_some_and(|token| token.revoked_at.is_some())
    {
        return Err((StatusCode::CONFLICT, "cannot edit a revoked token".into()));
    }

    match store
        .update(
            &id,
            name.into(),
            request.description,
            request.scopes,
            normalize_pattern(request.resource_pattern),
            request.required_headers,
        )
        .await
    {
        Ok(Some(token)) => {
            info!(token_id = %id, "Updated management access token");
            Ok(Json(AccessTokenMeta::from_token(&token, Utc::now())))
        }
        Ok(None) => Err((StatusCode::NOT_FOUND, "access token not found".into())),
        Err(error) => Err((StatusCode::INTERNAL_SERVER_ERROR, format!("failed to update token: {error}"))),
    }
}

pub async fn revoke_access_token(
    State(store): State<Arc<FsAccessTokenStore>>,
    Path(id): Path<String>,
    delegation: Option<Extension<PatDelegationContext>>,
) -> Result<StatusCode, (StatusCode, String)> {
    validate_target_authority(
        &store,
        delegation
            .as_ref()
            .map(|Extension(context)| context),
        &id,
    )?;
    match store.revoke(&id).await {
        Ok(Some(_)) => Ok(StatusCode::NO_CONTENT),
        Ok(None) => Err((StatusCode::NOT_FOUND, "access token not found".into())),
        Err(error) => Err((StatusCode::INTERNAL_SERVER_ERROR, format!("failed to revoke token: {error}"))),
    }
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone;

    use super::*;

    #[test]
    fn resolves_exact_and_never_expiry() {
        let now = Utc
            .with_ymd_and_hms(2026, 9, 9, 12, 0, 0)
            .unwrap();
        let exact = now + Duration::hours(6);

        assert_eq!(resolve_expiry(now, Some(exact)), Ok(Some(exact)));
        assert_eq!(resolve_expiry(now, None), Ok(None));
    }

    #[test]
    fn rejects_out_of_range_expiry() {
        let now = Utc
            .with_ymd_and_hms(2026, 9, 9, 12, 0, 0)
            .unwrap();

        assert!(resolve_expiry(now, Some(now)).is_err());
        assert!(resolve_expiry(now, Some(now + Duration::days(i64::from(MAX_EXPIRY_DAYS) + 1))).is_err());
    }

    #[test]
    fn create_request_rejects_removed_relative_expiry_field() {
        let request = serde_json::json!({
            "name": "service",
            "expires_in_days": 30
        });
        assert!(serde_json::from_value::<CreateAccessTokenRequest>(request).is_err());
    }

    #[test]
    fn scoped_pat_delegation_requires_a_non_empty_subset() {
        let parent = vec!["secrets.view".to_string(), "secrets.edit".to_string()];

        assert!(validate_delegated_scopes(Some(&parent), &["secrets.view".to_string()]).is_ok());
        assert!(validate_delegated_scopes(Some(&parent), &["secrets.delete".to_string()]).is_err());
        assert!(validate_delegated_scopes(Some(&parent), &[]).is_err());
        assert!(validate_delegated_scopes(None, &[]).is_ok());
    }

    #[test]
    fn delegated_lineage_is_bounded() {
        let parent = PatDelegationContext {
            token_id: "parent".to_string(),
            delegation_depth: MAX_DELEGATION_DEPTH - 1,
            resource_scoped: false,
        };
        assert_eq!(delegated_lineage(Some(&parent)), Ok((Some("parent".to_string()), MAX_DELEGATION_DEPTH)));

        let deepest = PatDelegationContext {
            token_id: "deepest".to_string(),
            delegation_depth: MAX_DELEGATION_DEPTH,
            resource_scoped: false,
        };
        assert!(delegated_lineage(Some(&deepest)).is_err());
        assert_eq!(delegated_lineage(None), Ok((None, 0)));

        let resource_scoped = PatDelegationContext {
            token_id: "scoped".to_string(),
            delegation_depth: 0,
            resource_scoped: true,
        };
        assert!(delegated_lineage(Some(&resource_scoped)).is_err());
        assert!(validate_delegation_authority(Some(&resource_scoped)).is_err());
    }

    #[tokio::test]
    async fn resource_scoped_pat_cannot_delegate_at_handler_boundary() {
        let directory = tempfile::tempdir().unwrap();
        let store = Arc::new(
            FsAccessTokenStore::new(directory.path())
                .await
                .unwrap(),
        );
        let scopes = vec!["secrets.view".to_string()];
        let result = create_access_token(
            State(store.clone()),
            Extension(Arc::new(RbacConfig::default())),
            Some(Extension(AuthGuardOk("user-1".to_string()))),
            Some(Extension(PatContext(Some(scopes.clone())))),
            Some(Extension(PatDelegationContext {
                token_id: "resource-scoped-parent".to_string(),
                delegation_depth: 0,
                resource_scoped: true,
            })),
            None,
            Json(CreateAccessTokenRequest {
                name: "child".to_string(),
                description: String::new(),
                scopes,
                resource_pattern: None,
                required_headers: Vec::new(),
                expires_at: None,
            }),
        )
        .await;

        assert!(matches!(result, Err((StatusCode::FORBIDDEN, _))));
        assert!(store.list().is_empty());
    }

    // ── issue-time tenant-selector enforcement ──

    fn broad_tenant_selector_request() -> CreateAccessTokenRequest {
        CreateAccessTokenRequest {
            name: "az5-token".to_string(),
            description: String::new(),
            scopes: Vec::new(),
            resource_pattern: Some("TENANT:${x-external-account}:gateways:.*".to_string()),
            required_headers: vec![RequiredHeader {
                name: "x-external-account".to_string(),
                pattern: "[a-z0-9-]+".to_string(),
            }],
            expires_at: None,
        }
    }

    fn token(
        id: &str,
        parent_token_id: Option<&str>,
        delegation_depth: u32,
    ) -> AccessToken {
        AccessToken {
            id: id.into(),
            name: id.into(),
            description: String::new(),
            token_hash: hash_secret(&format!("agpat_{id}")),
            user_id: "user-1".into(),
            scopes: vec!["secrets.view".into()],
            resource_pattern: None,
            required_headers: Vec::new(),
            created_by: "user-1".into(),
            parent_token_id: parent_token_id.map(str::to_string),
            delegation_depth,
            created_at: Utc::now(),
            last_used_at: None,
            expires_at: None,
            revoked_at: None,
        }
    }

    fn delegation(token_id: &str) -> Option<Extension<PatDelegationContext>> {
        Some(Extension(PatDelegationContext {
            token_id: token_id.into(),
            delegation_depth: 0,
            resource_scoped: false,
        }))
    }

    #[tokio::test]
    async fn delegated_administration_is_limited_to_self_and_descendants() {
        let directory = tempfile::tempdir().unwrap();
        let store = Arc::new(
            FsAccessTokenStore::new(directory.path())
                .await
                .unwrap(),
        );
        store
            .create(token("root", None, 0))
            .await
            .unwrap();
        store
            .create(token("child", Some("root"), 1))
            .await
            .unwrap();
        store
            .create(token("unrelated", None, 0))
            .await
            .unwrap();

        let Json(list) = list_access_tokens(State(store.clone()), delegation("root")).await;
        let mut ids: Vec<_> = list["access_tokens"]
            .as_array()
            .unwrap()
            .iter()
            .map(|token| token["id"].as_str().unwrap())
            .collect();
        ids.sort_unstable();
        assert_eq!(ids, vec!["child", "root"]);

        assert!(
            get_access_token(State(store.clone()), Path("child".into()), delegation("root"))
                .await
                .is_ok()
        );
        assert!(matches!(
            get_access_token(State(store.clone()), Path("unrelated".into()), delegation("root")).await,
            Err((StatusCode::NOT_FOUND, _))
        ));

        let update = update_access_token(
            State(store.clone()),
            Extension(Arc::new(RbacConfig::default())),
            Path("unrelated".into()),
            Some(Extension(PatContext(Some(vec!["secrets.view".into()])))),
            delegation("root"),
            None,
            Json(UpdateAccessTokenRequest {
                name: "changed".into(),
                description: String::new(),
                scopes: vec!["secrets.view".into()],
                resource_pattern: None,
                required_headers: Vec::new(),
            }),
        )
        .await;
        assert!(matches!(update, Err((StatusCode::FORBIDDEN, _))));

        let revoke = revoke_access_token(State(store.clone()), Path("unrelated".into()), delegation("root")).await;
        assert!(matches!(revoke, Err((StatusCode::FORBIDDEN, _))));
        assert!(
            store
                .get("unrelated")
                .unwrap()
                .revoked_at
                .is_none()
        );

        let Json(all) = list_access_tokens(State(store), None).await;
        assert_eq!(
            all["access_tokens"]
                .as_array()
                .unwrap()
                .len(),
            3
        );
    }

    #[tokio::test]
    async fn create_access_token_rejects_broad_tenant_selector_without_trusted_edge() {
        let directory = tempfile::tempdir().unwrap();
        let store = Arc::new(
            FsAccessTokenStore::new(directory.path())
                .await
                .unwrap(),
        );

        let result = create_access_token(
            State(store.clone()),
            Extension(Arc::new(RbacConfig::default())),
            Some(Extension(AuthGuardOk("user-1".to_string()))),
            None,
            None,
            None, // no tenancy config configured
            Json(broad_tenant_selector_request()),
        )
        .await;

        let Err((status, message)) = result else {
            panic!("expected broad tenant selector to be rejected");
        };
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(message.contains("broad"), "message should explain the rejection: {message}");
        assert!(message.contains("x-external-account"), "message should name the offending header: {message}");
        assert!(store.list().is_empty());
    }

    #[tokio::test]
    async fn create_access_token_accepts_exact_literal_tenant_selector() {
        let directory = tempfile::tempdir().unwrap();
        let store = Arc::new(
            FsAccessTokenStore::new(directory.path())
                .await
                .unwrap(),
        );

        let mut request = broad_tenant_selector_request();
        request.required_headers = vec![RequiredHeader {
            name: "x-external-account".to_string(),
            pattern: "tenant-a".to_string(),
        }];

        let result = create_access_token(
            State(store.clone()),
            Extension(Arc::new(RbacConfig::default())),
            Some(Extension(AuthGuardOk("user-1".to_string()))),
            None,
            None,
            None, // no tenancy config needed for an exact selector
            Json(request),
        )
        .await;

        assert!(result.is_ok(), "exact-literal selector should be accepted");
        assert_eq!(store.list().len(), 1);
    }

    #[tokio::test]
    async fn create_access_token_accepts_broad_tenant_selector_with_trusted_edge() {
        let directory = tempfile::tempdir().unwrap();
        let store = Arc::new(
            FsAccessTokenStore::new(directory.path())
                .await
                .unwrap(),
        );
        let tenancy = crate::tenancy::TenancyConfig {
            trusted_tenant_header: Some(crate::tenancy::TrustedTenantHeader {
                header: "x-external-account".to_string(),
                edge_strips_client_values: true,
            }),
        };

        let result = create_access_token(
            State(store.clone()),
            Extension(Arc::new(RbacConfig::default())),
            Some(Extension(AuthGuardOk("user-1".to_string()))),
            None,
            None,
            Some(Extension(Arc::new(tenancy))),
            Json(broad_tenant_selector_request()),
        )
        .await;

        assert!(result.is_ok(), "broad selector should be accepted behind a trusted, header-stripping edge");
        assert_eq!(store.list().len(), 1);
    }
}
