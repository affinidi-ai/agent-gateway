use std::sync::Arc;

use axum::routing::{delete, get, post, put};
use axum::{Extension, Router};

use crate::auth_manager::middleware::{RbacGuard, maybe_gate};
use crate::rbac::{Feature, RbacConfig};

use super::handlers;
use super::store::FsAccessTokenStore;

pub fn create_access_tokens_router(
    store: Arc<FsAccessTokenStore>,
    rbac_config: Arc<RbacConfig>,
    tenancy_config: Arc<crate::tenancy::TenancyConfig>,
    guard: Option<RbacGuard>,
) -> Router {
    Router::new()
        .route(
            "/api/v1/access-tokens",
            maybe_gate(guard.as_ref(), get(handlers::list_access_tokens), Feature::AccessTokensView),
        )
        .route(
            "/api/v1/access-tokens",
            maybe_gate(guard.as_ref(), post(handlers::create_access_token), Feature::AccessTokensEdit),
        )
        .route(
            "/api/v1/access-tokens/{id}",
            maybe_gate(guard.as_ref(), get(handlers::get_access_token), Feature::AccessTokensView),
        )
        .route(
            "/api/v1/access-tokens/{id}",
            maybe_gate(guard.as_ref(), put(handlers::update_access_token), Feature::AccessTokensEdit),
        )
        .route(
            "/api/v1/access-tokens/{id}",
            maybe_gate(guard.as_ref(), delete(handlers::revoke_access_token), Feature::AccessTokensDelete),
        )
        .layer(Extension(tenancy_config))
        .layer(Extension(rbac_config))
        .with_state(store)
}
