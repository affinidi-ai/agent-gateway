// Reserved: feature-gated (`didwebvh`) did:webvh implementation. Kept with a
// documented module-wide allow — a large serde/crypto surface where per-item
// scoping would be high-churn, low-value; swept only if the feature is retired.
#![allow(dead_code)]

use url::Url;

pub mod create;
pub mod handlers;
pub mod identifier;
pub mod identity_manager;
pub mod log;
pub mod resolver;
pub mod scid;
pub mod surface_integration;
pub mod trust_computer;
pub mod types;
pub mod verifier;

/// Build the publication base URL for a DID domain.
///
/// Localhost DID methods resolve over HTTP, while non-localhost domains resolve
/// over HTTPS.
pub(crate) fn base_url_for_domain(domain: &str) -> String {
    let trimmed = domain.trim_end_matches('/');
    let host = Url::parse(&format!("http://{trimmed}"))
        .ok()
        .and_then(|url| {
            url.host_str()
                .map(str::to_owned)
        });
    let scheme = if host.as_deref() == Some("localhost") {
        "http"
    } else {
        "https"
    };
    format!("{scheme}://{trimmed}/")
}

// Re-export commonly used types
pub use handlers::{
    DidWebVhApiState, create_identity, delete_identity, generate_parallel_did_web, get_identity, get_identity_history,
    get_policy_config, list_identities, resolve_did, rotate_keys, serve_did_log, transfer_ownership, update_identity,
    update_policy_config, verify_identity,
};
pub(crate) use handlers::{generate_ed25519_keypair, generate_random_dna};
pub use identity_manager::{DidWebVhIdentityStore, FileSystemDidWebVhIdentityStore};
pub use surface_integration::{SurfaceDidContext, load_surface_identity};
pub use types::LogEntry;

#[cfg(test)]
mod tests {
    use super::base_url_for_domain;

    #[test]
    fn localhost_did_domain_uses_http_base_url() {
        assert_eq!(base_url_for_domain("localhost:8080"), "http://localhost:8080/");
    }

    #[test]
    fn fqdn_did_domain_uses_https_base_url() {
        assert_eq!(base_url_for_domain("agent-gateway-1.example.com"), "https://agent-gateway-1.example.com/");
    }
}
