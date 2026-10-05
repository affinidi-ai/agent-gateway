// Handler modules for Identity API
pub mod agents;
pub mod audit_log;
pub mod config;
pub mod credentials;
pub mod debug_export;
pub mod didcomm;
pub mod health;
pub mod limits;
pub mod logs;
pub mod metrics;
pub mod metrics_config;
pub mod onboarding;
pub mod policy_definitions;
pub mod policy_validation;
pub mod settings;
mod surface_tenancy;
pub mod surfaces;
pub mod tenant_ownership;
pub mod trust_check_predefined;
pub mod user_settings;
pub mod version;

// Re-export commonly used types and functions for convenience
pub use agents::get_agents;
pub use config::{
    get_networking_config, get_payment_policy, get_surface_routing_config, reload_configuration, reload_single_channel,
};
pub use credentials::{
    get_did_document, issue_credential, resolve_did_document, resolve_did_document_spec, serve_agent_did_document,
    serve_gateway_did_document, serve_gateway_did_jsonl, serve_gateway_did_witness, serve_surface_did_jsonl,
    serve_surface_did_witness,
};
pub use debug_export::export_storage;
pub use didcomm::{didcomm_endpoint, didcomm_ws_endpoint};
pub use health::{alive_check, health_check};
pub use limits::list_limits;
pub use logs::{download_logs, truncate_old_logs};
pub use metrics::{prometheus_metrics, truncate_metrics};
pub use metrics_config::{get_metrics_config, get_otlp_status, test_otlp_connection, update_metrics_config};
pub use onboarding::{
    OnboardingSessionManager, create_temp_onboard_surface, delete_temp_onboard_channel, handle_onboarding_message,
    serve_onboarding_agent_card,
};
pub use policy_definitions::{
    create_policy_definition, delete_policy_definition, get_policy_assignments, get_policy_definition,
    list_policy_definitions, list_policy_versions, policy_definition_impact, simulate_policy_definition,
    update_policy_assignments, update_policy_definition,
};
pub use policy_validation::validate_policy;
pub use settings::{get_settings, reset_settings, update_settings};
pub use surfaces::{
    create_surface, create_variant, delete_surface, delete_variant, get_resolved_variant, get_surface, list_surfaces,
    promote_variant_to_default, update_surface, update_variant,
};
pub use trust_check_predefined::list_predefined_trust_check_queries;
pub use user_settings::{get_user_settings, get_user_settings_overrides, reset_user_settings, update_user_settings};
pub use version::get_version;
