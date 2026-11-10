//! Configuration module re-exports

pub mod agent_surface;
mod agent_surface_accessors;
pub(crate) mod agent_surface_compat;
pub mod agent_surface_variants;
mod bootstrap;
pub mod credential_policy;
pub mod encryption_config;
pub mod header_metadata_mapping;
pub mod limits_config;
pub mod loaders;
pub mod metrics_config;
pub mod network;
mod pepper_cache_config;
mod proxy;
pub mod rbac_config;
pub mod route_claims;
pub mod target_auth_rules;
pub mod types;

// Re-export all public types
pub use credential_policy::init_credential_policy;
pub use encryption_config::*;
pub use limits_config::*;
pub use metrics_config::*;
pub use network::*;
pub use pepper_cache_config::PepperCacheConfig;
pub(crate) use proxy::{
    fall_back_to_first_source_auth_method, fall_back_to_first_source_auth_methods_in_memory,
    log_additional_source_auth_method_notices, log_legacy_access_point_notices, log_source_auth_fallbacks,
    log_unchecked_audience_warnings, validate_source_auth_config, validate_source_auth_method,
};
pub use rbac_config::*;
pub use types::*;
