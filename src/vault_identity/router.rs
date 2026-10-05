// Router for vault identity endpoints

use super::handlers::*;
use crate::auth_manager::middleware::{RbacGuard, maybe_gate};
use crate::identity::VCIssuer;
use crate::rbac::Feature;
use axum::{Router, routing::post};
use std::sync::Arc;

/// Create the vault identity router. When `gate` is `Some`, the identity
/// generation route is gated by `IdentityIssue` (minting DIDs is admin-only).
pub fn create_vault_identity_router(
    vc_issuer: Arc<VCIssuer>,
    gate: Option<RbacGuard>,
) -> Router {
    let g = gate.as_ref();
    Router::new()
        .route("/api/v1/vault/identity/generate", maybe_gate(g, post(generate_identity), Feature::IdentityIssue))
        .with_state(vc_issuer)
}
