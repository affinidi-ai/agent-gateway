//! Router for certificate management endpoints

use super::{CertificateStore, handlers};
use crate::auth_manager::middleware::{RbacGuard, maybe_gate};
use crate::rbac::Feature;
use axum::{
    Router,
    routing::{delete, get, post, put},
};
use std::sync::Arc;
use tracing::info;

/// Create the certificates router. When `gate` is `Some`, mutating routes
/// (POST/PUT/DELETE) are wrapped with `CertificatesEdit` RBAC enforcement.
pub fn create_certificates_router(
    store: Arc<dyn CertificateStore>,
    gate: Option<RbacGuard>,
) -> Router {
    info!(
        "[Certificates Router] Creating certificates router with routes: /api/v1/certificates/, /api/v1/certificates/{{id}}"
    );
    let g = gate.as_ref();
    Router::new()
        .route("/api/v1/certificates", maybe_gate(g, get(handlers::list_certificates), Feature::CertificatesView))
        .route("/api/v1/certificates", maybe_gate(g, post(handlers::create_certificate), Feature::CertificatesEdit))
        .route("/api/v1/certificates/", maybe_gate(g, get(handlers::list_certificates), Feature::CertificatesView))
        .route("/api/v1/certificates/", maybe_gate(g, post(handlers::create_certificate), Feature::CertificatesEdit))
        .route("/api/v1/certificates/{id}", maybe_gate(g, get(handlers::get_certificate), Feature::CertificatesView))
        .route("/api/v1/certificates/{id}", maybe_gate(g, put(handlers::update_certificate), Feature::CertificatesEdit))
        .route(
            "/api/v1/certificates/{id}",
            maybe_gate(g, delete(handlers::delete_certificate), Feature::CertificatesEdit),
        )
        .with_state(store)
}
