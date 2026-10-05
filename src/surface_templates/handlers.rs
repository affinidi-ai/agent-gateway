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
use crate::tenancy::{PatTenantContext, ResourceKind, can_access, scope_allows_resource, tenant_for_create};

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
    let tpl = req.into_template(id, now);
    if !template_allowed(&tpl, &context, &scope) {
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
    Json(mut tpl): Json<SurfaceTemplate>,
) -> Result<Json<SurfaceTemplate>, TemplateApiError> {
    let s = store(&state)?;
    let existing = s
        .get(&id)
        .await
        .map_err(|e| TemplateApiError::InternalError(format!("get: {}", e)))?
        .ok_or_else(|| TemplateApiError::NotFound(format!("template '{}' not found", id)))?;
    if !template_allowed(&existing, &context, &scope) {
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
    s.save(&tpl)
        .await
        .map_err(|e| TemplateApiError::InternalError(format!("save: {}", e)))?;
    Ok(Json(tpl))
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
    if !template_allowed(&tpl, &context, &scope) {
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
    let s = store(&state)?;
    let existing = s
        .get(&id)
        .await
        .map_err(|e| TemplateApiError::InternalError(format!("get: {}", e)))?
        .ok_or_else(|| TemplateApiError::NotFound(format!("template '{}' not found", id)))?;
    if !template_allowed(&existing, &context, &scope) {
        return Err(TemplateApiError::Forbidden("Surface template is outside this token's permitted scope".into()));
    }
    if existing.builtin {
        return Err(TemplateApiError::Forbidden(format!("builtin template '{}' cannot be deleted", id)));
    }
    s.delete(&id)
        .await
        .map_err(|e| TemplateApiError::InternalError(format!("delete: {}", e)))?;
    Ok(StatusCode::NO_CONTENT)
}
