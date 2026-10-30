//! REST handlers for surface templates.

use axum::{
    Extension, Json,
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::Serialize;
use tracing::{debug, error, warn};

use super::filesystem::SurfaceTemplateStore;
use super::types::{CreateSurfaceTemplate, SurfaceTemplate};
use crate::auth_manager::pat::{PatContext, PatResourceScope};
use crate::identity::state::IdentityApiState;
use crate::tenancy::{
    PatTenantContext, ResourceKind, can_access, can_mutate, scope_allows_resource, tenant_for_create,
};

/// Application error type for surface template handlers.
#[derive(Debug)]
pub enum TemplateApiError {
    BadRequest(String),
    NotFound(String),
    Forbidden(String),
    InternalError(String),
}

impl IntoResponse for TemplateApiError {
    fn into_response(self) -> Response {
        let (status, message, details) = match &self {
            Self::BadRequest(m) => {
                warn!("Surface template API bad request: {}", m);
                (StatusCode::BAD_REQUEST, "Bad Request", Some(m.clone()))
            }
            Self::NotFound(m) => {
                warn!("Surface template API not found: {}", m);
                (StatusCode::NOT_FOUND, "Not Found", Some(m.clone()))
            }
            Self::Forbidden(m) => {
                warn!("Surface template API forbidden: {}", m);
                (StatusCode::FORBIDDEN, "Forbidden", Some(m.clone()))
            }
            Self::InternalError(m) => {
                error!("Surface template API internal error: {}", m);
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal Server Error", Some(m.clone()))
            }
        };
        (
            status,
            Json(ErrorBody {
                error: message.to_string(),
                details,
            }),
        )
            .into_response()
    }
}

#[derive(Debug, Serialize)]
struct ErrorBody {
    error: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    details: Option<String>,
}

fn store(state: &IdentityApiState) -> Result<&std::sync::Arc<super::FileSystemSurfaceTemplateStore>, TemplateApiError> {
    state
        .surface_template_store
        .as_ref()
        .ok_or_else(|| TemplateApiError::InternalError("Surface template store not initialized".to_string()))
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

fn template_allowed(
    template: &SurfaceTemplate,
    context: &Option<Extension<PatTenantContext>>,
    scope: &Option<Extension<PatResourceScope>>,
) -> bool {
    can_access(template.tenant_id.as_deref(), tenant_context(context))
        && scope_allows_resource(
            resource_scope(scope),
            tenant_context(context),
            ResourceKind::SurfaceTemplates,
            &template.id,
        )
}

/// May this caller change or delete the template? Requires [`can_mutate`]
/// ownership and a resource scope that matches the template id.
fn template_writable(
    template: &SurfaceTemplate,
    context: &Option<Extension<PatTenantContext>>,
    scope: &Option<Extension<PatResourceScope>>,
) -> bool {
    can_mutate(template.tenant_id.as_deref(), tenant_context(context))
        && scope_allows_resource(
            resource_scope(scope),
            tenant_context(context),
            ResourceKind::SurfaceTemplates,
            &template.id,
        )
}

/// `GET /v1/surface-templates`
pub async fn list_templates(
    State(state): State<IdentityApiState>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
) -> Result<Json<Vec<SurfaceTemplate>>, TemplateApiError> {
    let s = store(&state)?;
    let mut templates = s
        .list_all()
        .await
        .map_err(|e| TemplateApiError::InternalError(format!("list: {}", e)))?;
    templates.retain(|template| template_allowed(template, &context, &scope));
    // Stable order: builtins first (alphabetical), then user templates
    // (alphabetical by name). Makes the dashboard list deterministic
    // across reloads.
    templates.sort_by(|a, b| match (a.builtin, b.builtin) {
        (true, false) => std::cmp::Ordering::Less,
        (false, true) => std::cmp::Ordering::Greater,
        _ => a
            .name
            .to_lowercase()
            .cmp(&b.name.to_lowercase()),
    });
    debug!("Listed {} surface template(s)", templates.len());
    Ok(Json(templates))
}

/// `GET /v1/surface-templates/{id}`
pub async fn get_template(
    State(state): State<IdentityApiState>,
    Path(id): Path<String>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
) -> Result<Json<SurfaceTemplate>, TemplateApiError> {
    let s = store(&state)?;
    let tpl = s
        .get(&id)
        .await
        .map_err(|e| TemplateApiError::InternalError(format!("get: {}", e)))?
        .ok_or_else(|| TemplateApiError::NotFound(format!("template '{}' not found", id)))?;
    if !template_allowed(&tpl, &context, &scope) {
        return Err(TemplateApiError::NotFound(format!("template '{}' not found", id)));
    }
    Ok(Json(tpl))
}

/// `POST /v1/surface-templates`
pub async fn create_template(
    State(state): State<IdentityApiState>,
    pat: Option<Extension<PatContext>>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
    Json(mut req): Json<CreateSurfaceTemplate>,
) -> Result<(StatusCode, Json<SurfaceTemplate>), TemplateApiError> {
    let s = store(&state)?;

    req.tenant_id = tenant_for_create(req.tenant_id.take(), pat.is_some(), tenant_context(&context))
        .map_err(|message| TemplateApiError::Forbidden(message.to_string()))?;

    if req.name.trim().is_empty() {
        return Err(TemplateApiError::BadRequest("name must not be empty".to_string()));
    }

    let id = format!("user-{}", uuid::Uuid::new_v4());
    let now = chrono::Utc::now().to_rfc3339();
    let mut tpl = req.into_template(id, now);
    tpl.settle_surface_markers();
    if !template_writable(&tpl, &context, &scope) {
        return Err(TemplateApiError::Forbidden("Surface template is outside this token's permitted scope".into()));
    }

    s.save(&tpl)
        .await
        .map_err(|e| TemplateApiError::InternalError(format!("save: {}", e)))?;
    Ok((StatusCode::CREATED, Json(tpl)))
}

/// `PUT /v1/surface-templates/{id}`
pub async fn update_template(
    State(state): State<IdentityApiState>,
    Path(id): Path<String>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
    Json(tpl): Json<SurfaceTemplate>,
) -> Result<Json<SurfaceTemplate>, TemplateApiError> {
    update_stored_template(store(&state)?, id, &context, &scope, tpl)
        .await
        .map(Json)
}

async fn update_stored_template(
    s: &super::FileSystemSurfaceTemplateStore,
    id: String,
    context: &Option<Extension<PatTenantContext>>,
    scope: &Option<Extension<PatResourceScope>>,
    mut tpl: SurfaceTemplate,
) -> Result<SurfaceTemplate, TemplateApiError> {
    let existing = s
        .get(&id)
        .await
        .map_err(|e| TemplateApiError::InternalError(format!("get: {}", e)))?
        .ok_or_else(|| TemplateApiError::NotFound(format!("template '{}' not found", id)))?;
    if !template_allowed(&existing, context, scope) {
        return Err(TemplateApiError::NotFound(format!("template '{}' not found", id)));
    }
    if !template_writable(&existing, context, scope) {
        return Err(TemplateApiError::Forbidden("Surface template is outside this token's permitted scope".into()));
    }
    if existing.builtin {
        return Err(TemplateApiError::Forbidden(format!("builtin template '{}' cannot be modified", id)));
    }
    tpl.id = id;
    tpl.tenant_id = existing.tenant_id;
    tpl.builtin = false;
    tpl.created_at = existing.created_at;
    tpl.updated_at = Some(chrono::Utc::now().to_rfc3339());
    if tpl.name.trim().is_empty() {
        return Err(TemplateApiError::BadRequest("name must not be empty".to_string()));
    }
    tpl.settle_surface_markers();
    s.save(&tpl)
        .await
        .map_err(|e| TemplateApiError::InternalError(format!("save: {}", e)))?;
    Ok(tpl)
}

/// `GET /v1/surface-templates/{id}/export`
///
/// Returns the raw template JSON with a `Content-Disposition`
/// attachment header so browsers download it as a portable
/// `*.surface-template.json` file. Server-managed fields
/// (`builtin`, `created_at`, `updated_at`) are stripped so the
/// exported file is round-trippable across gateways.
pub async fn export_template(
    State(state): State<IdentityApiState>,
    Path(id): Path<String>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
) -> Result<Response, TemplateApiError> {
    let s = store(&state)?;
    let mut tpl = s
        .get(&id)
        .await
        .map_err(|e| TemplateApiError::InternalError(format!("get: {}", e)))?
        .ok_or_else(|| TemplateApiError::NotFound(format!("template '{}' not found", id)))?;
    if !template_allowed(&tpl, &context, &scope) {
        return Err(TemplateApiError::NotFound(format!("template '{}' not found", id)));
    }
    // Strip runtime / origin fields so the file is portable.
    tpl.tenant_id = None;
    tpl.builtin = false;
    tpl.created_at = None;
    tpl.updated_at = None;
    let body =
        serde_json::to_vec_pretty(&tpl).map_err(|e| TemplateApiError::InternalError(format!("serialize: {}", e)))?;
    let safe_id = id.replace(|c: char| !c.is_ascii_alphanumeric() && c != '-' && c != '_', "_");
    let filename = format!("{}.surface-template.json", safe_id);
    let mut response = (StatusCode::OK, body).into_response();
    response.headers_mut().insert(
        axum::http::header::CONTENT_TYPE,
        "application/json"
            .parse()
            .unwrap(),
    );
    response.headers_mut().insert(
        axum::http::header::CONTENT_DISPOSITION,
        format!("attachment; filename=\"{}\"", filename)
            .parse()
            .unwrap(),
    );
    Ok(response)
}

/// `POST /v1/surface-templates/import`
///
/// Accepts a `SurfaceTemplate` JSON body (typically the contents of a
/// previously-exported file) and persists it as a fresh user template.
/// If the incoming id collides with an existing template, the import
/// re-assigns a new id rather than failing — so users can re-import
/// the same file repeatedly to clone a template.
pub async fn import_template(
    State(state): State<IdentityApiState>,
    pat: Option<Extension<PatContext>>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
    Json(mut tpl): Json<SurfaceTemplate>,
) -> Result<(StatusCode, Json<SurfaceTemplate>), TemplateApiError> {
    let s = store(&state)?;
    // Server-controlled fields.
    tpl.builtin = false;
    tpl.tenant_id = tenant_for_create(tpl.tenant_id.take(), pat.is_some(), tenant_context(&context))
        .map_err(|message| TemplateApiError::Forbidden(message.to_string()))?;
    if tpl.name.trim().is_empty() {
        return Err(TemplateApiError::BadRequest("name must not be empty".to_string()));
    }
    if tpl.id.trim().is_empty()
        || s.get(&tpl.id)
            .await
            .map_err(|e| TemplateApiError::InternalError(format!("get: {}", e)))?
            .is_some()
    {
        tpl.id = format!("user-{}", uuid::Uuid::new_v4());
    }
    let now = chrono::Utc::now().to_rfc3339();
    tpl.created_at = Some(now.clone());
    tpl.updated_at = Some(now);
    tpl.settle_surface_markers();
    if !template_writable(&tpl, &context, &scope) {
        return Err(TemplateApiError::Forbidden("Surface template is outside this token's permitted scope".into()));
    }
    s.save(&tpl)
        .await
        .map_err(|e| TemplateApiError::InternalError(format!("save: {}", e)))?;
    debug!("Imported surface template '{}' ({})", tpl.name, tpl.id);
    Ok((StatusCode::CREATED, Json(tpl)))
}

/// `DELETE /v1/surface-templates/{id}`
pub async fn delete_template(
    State(state): State<IdentityApiState>,
    Path(id): Path<String>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
) -> Result<StatusCode, TemplateApiError> {
    delete_stored_template(store(&state)?, &id, &context, &scope).await
}

async fn delete_stored_template(
    s: &super::FileSystemSurfaceTemplateStore,
    id: &str,
    context: &Option<Extension<PatTenantContext>>,
    scope: &Option<Extension<PatResourceScope>>,
) -> Result<StatusCode, TemplateApiError> {
    let existing = s
        .get(id)
        .await
        .map_err(|e| TemplateApiError::InternalError(format!("get: {}", e)))?
        .ok_or_else(|| TemplateApiError::NotFound(format!("template '{}' not found", id)))?;
    if !template_allowed(&existing, context, scope) {
        return Err(TemplateApiError::NotFound(format!("template '{}' not found", id)));
    }
    if !template_writable(&existing, context, scope) {
        return Err(TemplateApiError::Forbidden("Surface template is outside this token's permitted scope".into()));
    }
    if existing.builtin {
        return Err(TemplateApiError::Forbidden(format!("builtin template '{}' cannot be deleted", id)));
    }
    s.delete(id)
        .await
        .map_err(|e| TemplateApiError::InternalError(format!("delete: {}", e)))?;
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_tenant_may_read_an_appliance_wide_template_but_not_change_it() {
        let tenant = Some(Extension(PatTenantContext {
            token_id: "token-a".into(),
            tenant_id: "tenant-a".into(),
        }));
        let mut record = serde_json::from_value::<crate::surface_templates::types::CreateSurfaceTemplate>(
            serde_json::json!({ "name": "Template" }),
        )
        .unwrap()
        .into_template("template-a".into(), "2026-01-01T00:00:00Z".into());
        record.tenant_id = None;
        assert!(template_allowed(&record, &tenant, &None));
        assert!(!template_writable(&record, &tenant, &None));
        assert!(template_writable(&record, &None, &None));

        record.tenant_id = Some("tenant-a".into());
        assert!(template_writable(&record, &tenant, &None));

        record.tenant_id = Some("tenant-b".into());
        assert!(!template_writable(&record, &tenant, &None));
    }

    async fn stored_template(
        tenant_id: Option<&str>
    ) -> (super::super::FileSystemSurfaceTemplateStore, SurfaceTemplate, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let store = super::super::FileSystemSurfaceTemplateStore::new(dir.path().join("templates"), None)
            .await
            .unwrap();
        let mut template = serde_json::from_value::<crate::surface_templates::types::CreateSurfaceTemplate>(
            serde_json::json!({ "name": "Operator template" }),
        )
        .unwrap()
        .into_template("template-a".into(), "2026-01-01T00:00:00Z".into());
        template.tenant_id = tenant_id.map(str::to_string);
        store
            .save(&template)
            .await
            .unwrap();
        (store, template, dir)
    }

    fn tenant_a() -> Option<Extension<PatTenantContext>> {
        Some(Extension(PatTenantContext {
            token_id: "token-a".into(),
            tenant_id: "tenant-a".into(),
        }))
    }

    fn renamed(template: &SurfaceTemplate) -> SurfaceTemplate {
        let mut renamed = template.clone();
        renamed.name = "Tenant template".into();
        renamed
    }

    #[tokio::test]
    async fn a_tenant_token_cannot_update_or_delete_an_appliance_wide_template() {
        let (store, template, _dir) = stored_template(None).await;
        assert!(template_allowed(&template, &tenant_a(), &None));

        let update = update_stored_template(&store, template.id.clone(), &tenant_a(), &None, renamed(&template)).await;
        assert!(matches!(update, Err(TemplateApiError::Forbidden(_))), "update: {update:?}");

        let delete = delete_stored_template(&store, &template.id, &tenant_a(), &None).await;
        assert!(matches!(delete, Err(TemplateApiError::Forbidden(_))), "delete: {delete:?}");

        let after = store
            .get(&template.id)
            .await
            .unwrap()
            .expect("appliance-wide template must survive");
        assert_eq!(after.name, "Operator template");
        assert_eq!(after.updated_at, template.updated_at);
    }

    #[tokio::test]
    async fn another_tenants_template_is_not_found_on_update_or_delete() {
        let (store, template, _dir) = stored_template(Some("tenant-b")).await;

        let update = update_stored_template(&store, template.id.clone(), &tenant_a(), &None, renamed(&template)).await;
        assert!(matches!(update, Err(TemplateApiError::NotFound(_))), "update: {update:?}");

        let delete = delete_stored_template(&store, &template.id, &tenant_a(), &None).await;
        assert!(matches!(delete, Err(TemplateApiError::NotFound(_))), "delete: {delete:?}");

        let after = store
            .get(&template.id)
            .await
            .unwrap()
            .expect("another tenant's template must survive");
        assert_eq!(after.name, "Operator template");
    }

    #[tokio::test]
    async fn a_tenant_token_can_update_and_delete_its_own_template() {
        let (store, template, _dir) = stored_template(Some("tenant-a")).await;

        let updated = update_stored_template(&store, template.id.clone(), &tenant_a(), &None, renamed(&template))
            .await
            .unwrap();
        assert_eq!(updated.name, "Tenant template");
        assert_eq!(updated.tenant_id.as_deref(), Some("tenant-a"));

        let status = delete_stored_template(&store, &template.id, &tenant_a(), &None)
            .await
            .unwrap();
        assert_eq!(status, StatusCode::NO_CONTENT);
        assert!(
            store
                .get(&template.id)
                .await
                .unwrap()
                .is_none()
        );
    }

    fn fabric_surface(trust_check_split: Option<bool>) -> serde_json::Value {
        let mut surface = serde_json::json!({
            "name": "$NAME",
            "access_point": {"listen_address": "$HOST", "route": "$ROUTE", "protocol": "a2a"},
            "target": {
                "endpoint": "fabric://gw-b/surface-x",
                "trust_check_list": [{
                    "id": "fabric-target",
                    "trust_registry_id": "tr-1",
                    "query_type": "recognition",
                    "query": {"authority_id": "did:example:authority", "entity_id": "{{ target.did }}"}
                }]
            },
            "transit": {"points": [{"alias": "partner-a", "target_endpoint": "https://a.example/a2a"}]}
        });
        if let Some(split) = trust_check_split {
            surface["trust_check_split"] = serde_json::json!(split);
        }
        surface
    }

    async fn update_and_reload(surface: serde_json::Value) -> (serde_json::Value, serde_json::Value) {
        let (store, template, dir) = stored_template(None).await;
        let mut update = template.clone();
        update.surface = Some(surface);
        let saved = update_stored_template(&store, template.id.clone(), &None, &None, update)
            .await
            .unwrap()
            .surface
            .expect("surface");
        let reloaded = super::super::FileSystemSurfaceTemplateStore::new(dir.path().join("templates"), None)
            .await
            .unwrap()
            .get(&template.id)
            .await
            .unwrap()
            .expect("template")
            .surface
            .expect("surface");
        (saved, reloaded)
    }

    #[tokio::test]
    async fn an_update_declaring_the_split_shape_is_kept_as_sent() {
        let (saved, reloaded) = update_and_reload(fabric_surface(Some(true))).await;

        assert_eq!(saved, fabric_surface(Some(true)), "a target list remains, so the marker is kept");
        assert_eq!(reloaded, saved, "a declared-shape template is never migrated");
        assert!(
            saved["transit"]["points"][0]
                .get("trust_check_list")
                .is_none()
        );
    }

    #[tokio::test]
    async fn an_update_without_the_marker_is_migrated() {
        let (saved, reloaded) = update_and_reload(fabric_surface(None)).await;

        assert_eq!(saved["trust_check_split"], serde_json::json!(true));
        assert_eq!(saved["target"]["trust_check_list"][0]["id"], "fabric-target", "fabric keeps its own list");
        assert_eq!(saved["transit"]["points"][0]["trust_check_list"][0]["id"], "fabric-target");
        assert_eq!(saved["transit"]["points"][0]["trust_check_migrated"], serde_json::json!(true));
        assert_eq!(reloaded, saved);
    }

    /// A template saved with a Transit Point that uses `source_auth` is marked
    /// `transit_point_source_auth` in its surface, whatever the update sent, as
    /// a saved surface is; one whose Transit Points do not use it is not.
    #[tokio::test]
    async fn an_update_marks_a_template_whose_transit_point_uses_source_auth() {
        let surface = |source_auth: bool, marker: bool| {
            let mut point = serde_json::json!({"alias": "partner", "target_endpoint": "https://partner.example/a2a",
                "require_transit_token": false, "allow_unauthenticated_callers": true});
            if source_auth {
                point = serde_json::json!({"alias": "partner", "target_endpoint": "https://partner.example/a2a",
                    "require_transit_token": false, "source_auth": {"type": "api_key",
                        "extraction": {"source": "http_header", "field": "X-API-Key"}, "secret_id": "partner-callers"}});
            }
            serde_json::json!({
                "name": "$NAME",
                "access_point": {"listen_address": "$HOST", "route": "$ROUTE", "protocol": "a2a"},
                "target": {"endpoint": "$TARGET_ENDPOINT"},
                "transit": {"points": [point]},
                "transit_point_source_auth": marker
            })
        };

        let (saved, reloaded) = update_and_reload(surface(true, false)).await;
        assert_eq!(saved["transit_point_source_auth"], serde_json::json!(true), "{saved}");
        assert_eq!(reloaded, saved);

        let (saved, reloaded) = update_and_reload(surface(false, true)).await;
        assert!(
            saved
                .get("transit_point_source_auth")
                .is_none(),
            "{saved}"
        );
        assert_eq!(reloaded, saved);
    }

    #[test]
    fn a_created_template_follows_the_declared_shape() {
        let create = |surface: serde_json::Value| {
            let mut template = serde_json::from_value::<crate::surface_templates::types::CreateSurfaceTemplate>(
                serde_json::json!({ "name": "Full", "kind": "full", "surface": surface }),
            )
            .unwrap()
            .into_template("template-f".into(), "2026-01-01T00:00:00Z".into());
            template.settle_surface_markers();
            template
                .surface
                .expect("surface")
        };

        let declared = create(fabric_surface(Some(true)));
        assert_eq!(declared, fabric_surface(Some(true)));

        let legacy = create(fabric_surface(None));
        assert_eq!(legacy["transit"]["points"][0]["trust_check_migrated"], serde_json::json!(true));
        assert_eq!(legacy["trust_check_split"], serde_json::json!(true));

        let mut without_target_list = fabric_surface(Some(true));
        without_target_list["target"]
            .as_object_mut()
            .unwrap()
            .remove("trust_check_list");
        let settled = create(without_target_list);
        assert!(
            settled
                .get("trust_check_split")
                .is_none(),
            "no target list, so no marker is persisted"
        );
    }

    #[test]
    fn a_created_template_without_a_surface_is_left_without_one() {
        let mut template = serde_json::from_value::<crate::surface_templates::types::CreateSurfaceTemplate>(
            serde_json::json!({ "name": "Partial" }),
        )
        .unwrap()
        .into_template("template-p".into(), "2026-01-01T00:00:00Z".into());
        template.settle_surface_markers();
        assert!(template.surface.is_none());
    }
}
