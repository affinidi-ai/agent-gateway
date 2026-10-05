//! Credential providers API router

use super::{handlers, storage::CredentialProviderStorage};
use crate::auth_manager::middleware::{RbacGuard, maybe_gate};
use crate::rbac::Feature;
use axum::{
    Router,
    routing::{delete, get, post, put},
};
use std::sync::Arc;

/// Create the credential providers API router
pub fn create_credential_providers_router(
    store: Arc<dyn CredentialProviderStorage>,
    secrets_store: Arc<dyn crate::secrets::SecretsStore>,
    oauth_callback_route: String,
    guard: Option<RbacGuard>,
    identity_strategies: Option<Arc<dyn crate::jwt_bearer::JwtVerificationStrategyStorage>>,
) -> Router {
    let state = handlers::CredentialProviderState {
        store,
        secrets_store,
        identity_strategies,
        oauth_callback_route,
    };
    let gate = guard.as_ref();
    Router::new()
        .route("/api/v1/credential-providers/validate", post(handlers::validate_provider))
        .route(
            "/api/v1/credential-providers",
            maybe_gate(gate, post(handlers::create_provider), Feature::CredentialProvidersEdit),
        )
        .route(
            "/api/v1/credential-providers",
            maybe_gate(gate, get(handlers::list_providers), Feature::CredentialProvidersView),
        )
        .route(
            "/api/v1/credential-providers/{id}",
            maybe_gate(gate, get(handlers::get_provider), Feature::CredentialProvidersView),
        )
        .route(
            "/api/v1/credential-providers/{id}",
            maybe_gate(gate, put(handlers::update_provider), Feature::CredentialProvidersEdit),
        )
        .route(
            "/api/v1/credential-providers/{id}",
            maybe_gate(gate, delete(handlers::delete_provider), Feature::CredentialProvidersDelete),
        )
        .with_state(state)
}
