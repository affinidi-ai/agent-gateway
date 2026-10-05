//! Secrets API router

use super::{SecretsStore, handlers};
use crate::auth_manager::middleware::{RbacGuard, maybe_gate};
use crate::rbac::Feature;
use axum::{
    Extension, Router,
    routing::{delete, get, post, put},
};
use std::sync::Arc;

/// Create the secrets API router. When `gate` is `Some`, mutating routes are
/// wrapped with RBAC enforcement (`SecretsEdit` / `SecretsDelete`).
pub fn create_secrets_router(
    secrets_store: Arc<dyn SecretsStore>,
    notification_store: Option<Arc<crate::integrations::FileSystemNotificationStore>>,
    secrets_cache: Option<crate::a2a::auth::SecretsCache>,
    gate: Option<RbacGuard>,
) -> Router {
    let g = gate.as_ref();
    Router::new()
        .route("/api/v1/secrets", maybe_gate(g, get(handlers::list_secrets), Feature::SecretsView))
        .route("/api/v1/secrets/", maybe_gate(g, get(handlers::list_secrets), Feature::SecretsView))
        .route("/api/v1/secrets/new", maybe_gate(g, post(handlers::create_secret), Feature::SecretsEdit))
        .route("/api/v1/secrets/{id}", maybe_gate(g, get(handlers::get_secret), Feature::SecretsView))
        .route("/api/v1/secrets/{id}", maybe_gate(g, put(handlers::update_secret), Feature::SecretsEdit))
        .route("/api/v1/secrets/{id}", maybe_gate(g, delete(handlers::delete_secret), Feature::SecretsDelete))
        .route("/api/v1/secrets/tag/{tag}", maybe_gate(g, get(handlers::find_by_tag), Feature::SecretsView))
        .layer(Extension(notification_store))
        .layer(Extension(secrets_cache))
        .with_state(secrets_store)
}
