//! JWT verification strategy router
//!
//! Registers the five CRUD endpoints under `/api/v1/jwt-verification-strategies`.

use axum::{
    Router,
    routing::{delete, get, post, put},
};

use super::handlers::{self, JwtVerificationStrategyState};

/// Create the JWT verification strategies router.
///
/// **Important:** the caller must `.layer` the session-auth middleware and the
/// `Extension<Arc<PasskeyStorage>>` / `Extension<Arc<RbacConfig>>` /
/// `Extension<Arc<JwksClient>>` extensions before merging this router (follow
/// the same pattern used for user-management routes in `src/identity/router.rs`).
pub fn create_jwt_verification_strategies_router(state: JwtVerificationStrategyState) -> Router {
    Router::new()
        // validate-jwks-uri must be registered BEFORE /{id} to avoid path conflicts
        .route("/v1/jwt-verification-strategies/validate-jwks-uri", post(handlers::validate_jwks_uri))
        .route("/v1/jwt-verification-strategies", post(handlers::create_strategy))
        .route("/v1/jwt-verification-strategies", get(handlers::list_strategies))
        .route("/v1/jwt-verification-strategies/{id}", get(handlers::get_strategy))
        .route("/v1/jwt-verification-strategies/{id}", put(handlers::update_strategy))
        .route("/v1/jwt-verification-strategies/{id}", delete(handlers::delete_strategy))
        .with_state(state)
}
