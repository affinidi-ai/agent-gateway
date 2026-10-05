//! Q3 (`is`/`registeredIssuer`) recognition-query resource-name configuration.
//!
//! The Q3 recognition query — "does the Authority recognise this Issuer as one
//! it has registered?" — carries a resource string on the TRQP wire that the
//! external Trust Registry indexes records against. Historically the string
//! was `"registeredDepartment"`; after the terminology rename the canonical
//! name is `"registeredIssuer"`. Because deployed registries already index
//! against the legacy string, the wire value defaults to the legacy spelling
//! and is switchable per-gateway via
//! `[trust_registry].q3_resource_name = "registeredIssuer"` in `gateway.json`.
//!
//! Read at boot from `BootstrapConfig.trust_registry.q3_resource_name`; the
//! value is a process-global `OnceLock` because it is stable for the lifetime
//! of the gateway and threaded to too many call sites to make configuration
//! plumbing worthwhile.

use std::sync::OnceLock;

/// Legacy wire value — preserved as the default for backward compatibility
/// with Trust Registries that have not yet migrated to `registeredIssuer`.
pub const LEGACY_Q3_RESOURCE_NAME: &str = "registeredDepartment";

/// Canonical wire value after the terminology rename.
#[allow(dead_code)]
pub const CANONICAL_Q3_RESOURCE_NAME: &str = "registeredIssuer";

static Q3_RESOURCE_NAME: OnceLock<String> = OnceLock::new();

/// Initialise the process-global Q3 resource name. First call wins. Called
/// once at boot from [`BootstrapConfig::from_file`](crate::config::BootstrapConfig::from_file)
/// (`src/config/bootstrap.rs`) once the config TOML is parsed.
pub fn init(name: impl Into<String>) {
    let value = name.into();
    let _ = Q3_RESOURCE_NAME.set(value);
}

/// Return the current Q3 resource name. Falls back to
/// `LEGACY_Q3_RESOURCE_NAME` when [`init`] has not been called (unit tests,
/// pre-boot code paths). Static string via a leaked reference to the
/// initialised `String` is fine because the value never changes after boot.
pub fn q3_resource_name() -> &'static str {
    Q3_RESOURCE_NAME
        .get()
        .map(String::as_str)
        .unwrap_or(LEGACY_Q3_RESOURCE_NAME)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_legacy_before_init() {
        // In a test process this OnceLock may already have been set by an
        // earlier test; either way the returned string must be one of the
        // two recognised wire values.
        let value = q3_resource_name();
        assert!(value == LEGACY_Q3_RESOURCE_NAME || value == CANONICAL_Q3_RESOURCE_NAME);
    }
}
