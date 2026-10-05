use axum::Json;
use serde::Serialize;

/// Version check response
#[derive(Debug, Serialize)]
pub struct VersionResponse {
    version: String,
}

/// Version endpoint
///
/// GET /api/v1/version
///
/// Response:
/// ```json
/// {
///   "version": "v0.1.0"
/// }
/// ```
pub async fn get_version() -> Json<VersionResponse> {
    // https://doc.rust-lang.org/cargo/reference/environment-variables.html#environment-variables-cargo-sets-for-crates
    Json(VersionResponse {
        version: env!("CARGO_PKG_VERSION").to_string(),
    })
}
