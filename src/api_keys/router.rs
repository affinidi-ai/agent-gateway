//! API Key router

use axum::{
    Extension, Router,
    routing::{delete, get, post},
};
use std::sync::Arc;

use super::handlers::{self, ApiKeyState};
use super::store::ApiKeyStore;
use crate::auth_manager::middleware::{RbacGuard, maybe_gate};
use crate::rbac::Feature;
use crate::surfaces::AgentSurfaceStore;

/// Create the API keys router
///
/// Mounts the following routes:
/// - GET    /api/v1/api-keys                         - List all keys across all agents
/// - GET    /api/v1/api-keys/{agent_id}             - List keys for an agent
/// - POST   /api/v1/api-keys/{agent_id}             - Create key (RBAC: ApiKeysEdit)
/// - GET    /api/v1/api-keys/{agent_id}/{key_id}    - Get key metadata (never the secret)
/// - POST   /api/v1/api-keys/{agent_id}/{key_id}/revoke  - Revoke key (RBAC: ApiKeysEdit)
/// - POST   /api/v1/api-keys/{agent_id}/{key_id}/rotate  - Rotate key (RBAC: ApiKeysEdit)
/// - DELETE /api/v1/api-keys/{agent_id}/{key_id}    - Delete key (RBAC: ApiKeysDelete)
///
/// When `gate` is `Some`, mutating routes are wrapped with RBAC enforcement;
/// when `None`, they remain ungated (preserves auth-disabled build behavior).
pub fn create_api_keys_router<S: ApiKeyStore + 'static>(
    store: Arc<S>,
    surface_store: Arc<dyn AgentSurfaceStore>,
    gate: Option<RbacGuard>,
) -> Router {
    let state: ApiKeyState = store;
    let g = gate.as_ref();

    Router::new()
        .route("/api/v1/api-keys", maybe_gate(g, get(handlers::list_all_keys), Feature::ApiKeysView))
        .route("/api/v1/api-keys/{agent_id}", maybe_gate(g, get(handlers::list_keys), Feature::ApiKeysView))
        .route("/api/v1/api-keys/{agent_id}", maybe_gate(g, post(handlers::create_key), Feature::ApiKeysEdit))
        .route("/api/v1/api-keys/{agent_id}/{key_id}", maybe_gate(g, get(handlers::get_key), Feature::ApiKeysView))
        .route(
            "/api/v1/api-keys/{agent_id}/{key_id}/revoke",
            maybe_gate(g, post(handlers::revoke_key), Feature::ApiKeysEdit),
        )
        .route(
            "/api/v1/api-keys/{agent_id}/{key_id}/rotate",
            maybe_gate(g, post(handlers::rotate_key), Feature::ApiKeysEdit),
        )
        .route(
            "/api/v1/api-keys/{agent_id}/{key_id}",
            maybe_gate(g, delete(handlers::delete_key), Feature::ApiKeysDelete),
        )
        .layer(Extension(surface_store))
        .with_state(state)
}
