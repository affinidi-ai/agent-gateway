//! Role-Based Access Control (RBAC) module

use crate::auth::types::UserRole;
use serde::{Deserialize, Deserializer, Serialize};
use std::collections::HashMap;

/// RBAC configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RbacConfig {
    /// Feature permissions map: feature_name -> required_role.
    /// Defaults to the hardened permission set so that a missing or partial
    /// `permissions` key in `rbac.json` never degrades to open access.
    /// When the key is present, the supplied entries are merged on top of
    /// the defaults — unlisted features keep their default role.
    #[serde(default = "default_permissions", deserialize_with = "deserialize_permissions_merged")]
    pub permissions: HashMap<String, String>,
}

fn deserialize_permissions_merged<'de, D>(deserializer: D) -> Result<HashMap<String, String>, D::Error>
where
    D: Deserializer<'de>,
{
    let overrides: HashMap<String, String> = HashMap::deserialize(deserializer)?;
    let normalized_overrides = normalize_legacy_permissions(overrides);
    let mut merged = default_permissions();
    merged.extend(normalized_overrides);
    Ok(merged)
}

/// Normalise deprecated permission keys to their canonical forms.
///
/// `departments.*` is the pre-rename name for what the platform now calls
/// `issuers.*`; operator-authored `rbac.json` files carrying the legacy prefix
/// are still accepted but a WARN is logged so the operator knows to update.
/// When both the legacy and canonical key are set, canonical wins.
fn normalize_legacy_permissions(map: HashMap<String, String>) -> HashMap<String, String> {
    let mut out = HashMap::with_capacity(map.len());
    let mut legacy_keys_present: Vec<String> = Vec::new();
    let mut canonical_keys_present: std::collections::HashSet<String> = std::collections::HashSet::new();
    for (key, value) in map {
        if let Some(rest) = key.strip_prefix("departments.") {
            let canonical = format!("issuers.{}", rest);
            legacy_keys_present.push(key.clone());
            // Canonical-wins semantics: only insert if the canonical form is not
            // already present in the operator's overrides.
            out.entry(canonical)
                .or_insert(value);
        } else {
            if key.starts_with("issuers.") {
                canonical_keys_present.insert(key.clone());
            }
            out.insert(key, value);
        }
    }
    for legacy in legacy_keys_present {
        let canonical = format!("issuers.{}", &legacy["departments.".len()..]);
        if canonical_keys_present.contains(&canonical) {
            tracing::warn!(
                legacy_key = %legacy,
                canonical_key = %canonical,
                "rbac.json defines both legacy '{}' and canonical '{}' permission keys; using the canonical value. Remove the legacy key.",
                legacy,
                canonical
            );
        } else {
            tracing::warn!(
                legacy_key = %legacy,
                canonical_key = %canonical,
                "rbac.json uses legacy permission key '{}'; use '{}' instead. Legacy key still honoured for backward compatibility.",
                legacy,
                canonical
            );
        }
    }
    out
}

/// Returns the fully-populated default permissions map.
/// Used by serde when the `permissions` key is absent during deserialization,
/// ensuring security-critical features are never left unrestricted.
fn default_permissions() -> HashMap<String, String> {
    RbacConfig::default().permissions
}

impl Default for RbacConfig {
    fn default() -> Self {
        let mut permissions = HashMap::new();
        // Settings - Admin only
        permissions.insert("settings.view".to_string(), "administrator".to_string());
        permissions.insert("settings.edit".to_string(), "administrator".to_string());
        // User Management - Admin only
        permissions.insert("users.view".to_string(), "administrator".to_string());
        permissions.insert("users.edit".to_string(), "administrator".to_string());
        permissions.insert("users.approve".to_string(), "administrator".to_string());
        permissions.insert("users.delete".to_string(), "administrator".to_string());
        // Gateway Management - Admin only (mutates gateway-wide registry; HIGH severity finding H2)
        permissions.insert("gateways.edit".to_string(), "administrator".to_string());
        permissions.insert("gateways.delete".to_string(), "administrator".to_string());
        // Mediator Management - PowerUser and above
        permissions.insert("mediators.edit".to_string(), "poweruser".to_string());
        permissions.insert("mediators.delete".to_string(), "poweruser".to_string());
        // MCP Proxy Management - PowerUser and above
        permissions.insert("mcp_proxies.view".to_string(), "poweruser".to_string());
        permissions.insert("mcp_proxies.edit".to_string(), "poweruser".to_string());
        permissions.insert("mcp_proxies.delete".to_string(), "poweruser".to_string());
        // A2A Proxy Management - PowerUser and above
        permissions.insert("a2a_proxies.view".to_string(), "poweruser".to_string());
        permissions.insert("a2a_proxies.edit".to_string(), "poweruser".to_string());
        permissions.insert("a2a_proxies.delete".to_string(), "poweruser".to_string());
        // Trust Registry Management - Admin only (gateway-wide trust source; HIGH severity finding H13)
        permissions.insert("trust_registries.edit".to_string(), "administrator".to_string());
        permissions.insert("trust_registries.delete".to_string(), "administrator".to_string());
        // Surface Management - Admin only (rewriting a surface redirects traffic and bypasses OPA / auth strategy; HIGH severity findings H1, H6, H16)
        permissions.insert("surfaces.edit".to_string(), "administrator".to_string());
        permissions.insert("surfaces.delete".to_string(), "administrator".to_string());
        permissions.insert("surfaces.capture".to_string(), "poweruser".to_string());
        // Policy Definitions - Admin only (global OPA policy registry; HIGH severity finding H4)
        permissions.insert("policies.view".to_string(), "administrator".to_string());
        permissions.insert("policies.edit".to_string(), "administrator".to_string());
        permissions.insert("policies.delete".to_string(), "administrator".to_string());
        // Configuration hot-reload - Admin only (HIGH severity finding H5)
        permissions.insert("config.reload".to_string(), "administrator".to_string());
        // API Keys (global + per-agent) - Admin only (HIGH severity findings H10, H11; BOLA owner-scoping tracked separately)
        permissions.insert("api_keys.view".to_string(), "administrator".to_string());
        permissions.insert("api_keys.edit".to_string(), "administrator".to_string());
        permissions.insert("api_keys.delete".to_string(), "administrator".to_string());
        permissions.insert("access_tokens.view".to_string(), "administrator".to_string());
        permissions.insert("access_tokens.edit".to_string(), "administrator".to_string());
        permissions.insert("access_tokens.delete".to_string(), "administrator".to_string());
        permissions.insert("tenant_ownership.manage".to_string(), "administrator".to_string());
        permissions.insert("credential_providers.view".to_string(), "administrator".to_string());
        permissions.insert("credential_providers.edit".to_string(), "administrator".to_string());
        permissions.insert("credential_providers.delete".to_string(), "administrator".to_string());
        // Certificates - Admin only (global certificates; HIGH severity finding H12)
        permissions.insert("certificates.edit".to_string(), "administrator".to_string());
        permissions.insert("certificates.view".to_string(), "administrator".to_string());
        // Integrations - reads are user-level; mutations are Admin only.
        permissions.insert("integrations.view".to_string(), "user".to_string());
        permissions.insert("integrations.edit".to_string(), "administrator".to_string());
        permissions.insert("integrations.delete".to_string(), "administrator".to_string());
        // Identity issuance - Admin only (mints new identities and credentials; HIGH severity findings H15, H18)
        permissions.insert("identity.issue".to_string(), "administrator".to_string());
        // OIDC Provider Management - Admin only
        permissions.insert("jwt_verification_strategies.view".to_string(), "administrator".to_string());
        permissions.insert("jwt_verification_strategies.edit".to_string(), "administrator".to_string());
        permissions.insert("jwt_verification_strategies.delete".to_string(), "administrator".to_string());
        // STS managed connections (RFC 8693 token-exchange clients) - Admin only
        permissions.insert("sts_clients.view".to_string(), "administrator".to_string());
        permissions.insert("sts_clients.edit".to_string(), "administrator".to_string());
        permissions.insert("sts_clients.delete".to_string(), "administrator".to_string());
        // Terms Management - Admin only
        permissions.insert("terms.view".to_string(), "administrator".to_string());
        permissions.insert("terms.edit".to_string(), "administrator".to_string());
        // Storage backup / restore / export - Admin only (full-instance access)
        permissions.insert("storage.admin".to_string(), "administrator".to_string());
        // Features accessible to all authenticated users (minimum role = user).
        // Explicitly listed so that default-deny does not lock them out.
        permissions.insert("gateways.view".to_string(), "user".to_string());
        permissions.insert("mediators.view".to_string(), "poweruser".to_string());
        permissions.insert("trust_registries.view".to_string(), "user".to_string());
        permissions.insert("surfaces.view".to_string(), "user".to_string());
        // Secrets - Admin only for all operations. There is no per-record owner, so a
        // read grant is a read of every credential the appliance holds.
        permissions.insert("secrets.view".to_string(), "administrator".to_string());
        permissions.insert("secrets.edit".to_string(), "administrator".to_string());
        permissions.insert("secrets.delete".to_string(), "administrator".to_string());
        // Delegation Vault management - Admin only. Listing enumerates and deleting mass-revokes
        // every user's/agent's delegated OAuth grants gateway-wide, so both are admin-only.
        permissions.insert("delegation_vault.view".to_string(), "administrator".to_string());
        permissions.insert("delegation_vault.delete".to_string(), "administrator".to_string());
        permissions.insert("notifications.view".to_string(), "user".to_string());
        permissions.insert("notifications.edit".to_string(), "poweruser".to_string());
        permissions.insert("notifications.delete".to_string(), "poweruser".to_string());
        permissions.insert("issuers.view".to_string(), "user".to_string());
        permissions.insert("issuers.edit".to_string(), "poweruser".to_string());
        permissions.insert("issuers.delete".to_string(), "poweruser".to_string());
        // Trust authorities govern who this gateway trusts, so writes are admin-only.
        permissions.insert("authorities.view".to_string(), "user".to_string());
        permissions.insert("authorities.edit".to_string(), "administrator".to_string());
        permissions.insert("authorities.delete".to_string(), "administrator".to_string());
        permissions.insert("metrics.view".to_string(), "user".to_string());
        permissions.insert("dashboard.view".to_string(), "user".to_string());
        permissions.insert("logs.view".to_string(), "user".to_string());
        permissions.insert("audit.view".to_string(), "administrator".to_string());
        // Payment records carry payer, amount and transaction ids with no per-record owner.
        permissions.insert("payments.view".to_string(), "poweruser".to_string());
        permissions.insert("payments.edit".to_string(), "administrator".to_string());
        permissions.insert("payments.delete".to_string(), "administrator".to_string());
        permissions.insert("payments.retry".to_string(), "poweruser".to_string());

        Self { permissions }
    }
}

/// Features that can be restricted
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Feature {
    // User Management
    UsersView,
    UsersEdit,
    UsersApprove,
    UsersDelete,

    // Gateway Management
    GatewaysView,
    GatewaysEdit,
    GatewaysDelete,

    // Mediator Management
    MediatorsView,
    MediatorsEdit,
    MediatorsDelete,

    // MCP Proxy Management
    McpProxiesView,
    McpProxiesEdit,
    McpProxiesDelete,

    // A2A Proxy Management
    A2aProxiesView,
    A2aProxiesEdit,
    A2aProxiesDelete,

    // Trust Registry Management
    TrustRegistriesView,
    TrustRegistriesEdit,
    TrustRegistriesDelete,

    // Vault Management
    SecretsView,
    SecretsEdit,
    SecretsDelete,

    // Delegation Vault Management - admin only (enumerate / mass-revoke delegated OAuth grants)
    DelegationVaultView,
    DelegationVaultDelete,

    // Notification Management
    NotificationsView,
    NotificationsEdit,
    NotificationsDelete,

    // Channel Management
    SurfacesView,
    SurfacesEdit,
    SurfacesDelete,
    SurfacesCapture,

    // Issuer Management (was: Department)
    IssuersView,
    IssuersEdit,
    IssuersDelete,

    // Authority Management (local trust-anchor register)
    AuthoritiesView,
    AuthoritiesEdit,
    AuthoritiesDelete,

    // System Settings
    SettingsView,
    SettingsEdit,

    // Terms Management
    TermsView,
    TermsEdit,

    // Metrics and Monitoring
    MetricsView,
    DashboardView,
    LogsView,
    AuditView,

    // Payment Management
    PaymentsView,
    PaymentsEdit,
    PaymentsDelete,
    PaymentsRetry,

    // OIDC Provider Management
    JwtVerificationStrategiesView,
    JwtVerificationStrategiesEdit,
    JwtVerificationStrategiesDelete,

    // STS managed connections (RFC 8693 token-exchange clients)
    StsClientsView,
    StsClientsEdit,
    StsClientsDelete,

    // Storage Backup / Restore / Export - full-instance access
    StorageAdmin,

    // Policy Definitions - global OPA policy registry (HIGH severity finding H4)
    PoliciesView,
    PoliciesEdit,
    PoliciesDelete,

    // Configuration hot-reload - swaps gateway state from disk (HIGH severity finding H5)
    ConfigReload,

    // API Keys (global + per-agent) - admin only (HIGH severity findings H10, H11)
    ApiKeysView,
    ApiKeysEdit,
    ApiKeysDelete,

    // Management API personal access tokens
    AccessTokensView,
    AccessTokensEdit,
    AccessTokensDelete,

    TenantOwnershipManage,

    CredentialProvidersView,
    CredentialProvidersEdit,
    CredentialProvidersDelete,

    // Certificates
    CertificatesView,
    CertificatesEdit,

    // Integrations - auth and notification pipelines (HIGH severity finding H14)
    IntegrationsView,
    IntegrationsEdit,
    IntegrationsDelete,

    // Identity issuance - mints new identities and credentials (HIGH severity findings H15, H18)
    IdentityIssue,
}

impl Feature {
    pub fn as_str(&self) -> &'static str {
        match self {
            Feature::UsersView => "users.view",
            Feature::UsersEdit => "users.edit",
            Feature::UsersApprove => "users.approve",
            Feature::UsersDelete => "users.delete",
            Feature::GatewaysView => "gateways.view",
            Feature::GatewaysEdit => "gateways.edit",
            Feature::GatewaysDelete => "gateways.delete",
            Feature::MediatorsView => "mediators.view",
            Feature::MediatorsEdit => "mediators.edit",
            Feature::MediatorsDelete => "mediators.delete",
            Feature::McpProxiesView => "mcp_proxies.view",
            Feature::McpProxiesEdit => "mcp_proxies.edit",
            Feature::McpProxiesDelete => "mcp_proxies.delete",
            Feature::A2aProxiesView => "a2a_proxies.view",
            Feature::A2aProxiesEdit => "a2a_proxies.edit",
            Feature::A2aProxiesDelete => "a2a_proxies.delete",
            Feature::TrustRegistriesView => "trust_registries.view",
            Feature::TrustRegistriesEdit => "trust_registries.edit",
            Feature::TrustRegistriesDelete => "trust_registries.delete",
            Feature::SecretsView => "secrets.view",
            Feature::SecretsEdit => "secrets.edit",
            Feature::SecretsDelete => "secrets.delete",
            Feature::DelegationVaultView => "delegation_vault.view",
            Feature::DelegationVaultDelete => "delegation_vault.delete",
            Feature::NotificationsView => "notifications.view",
            Feature::NotificationsEdit => "notifications.edit",
            Feature::NotificationsDelete => "notifications.delete",
            Feature::SurfacesView => "surfaces.view",
            Feature::SurfacesEdit => "surfaces.edit",
            Feature::SurfacesDelete => "surfaces.delete",
            Feature::SurfacesCapture => "surfaces.capture",
            Feature::IssuersView => "issuers.view",
            Feature::IssuersEdit => "issuers.edit",
            Feature::IssuersDelete => "issuers.delete",
            Feature::AuthoritiesView => "authorities.view",
            Feature::AuthoritiesEdit => "authorities.edit",
            Feature::AuthoritiesDelete => "authorities.delete",
            Feature::SettingsView => "settings.view",
            Feature::SettingsEdit => "settings.edit",
            Feature::TermsView => "terms.view",
            Feature::TermsEdit => "terms.edit",
            Feature::MetricsView => "metrics.view",
            Feature::DashboardView => "dashboard.view",
            Feature::LogsView => "logs.view",
            Feature::AuditView => "audit.view",
            Feature::PaymentsView => "payments.view",
            Feature::PaymentsEdit => "payments.edit",
            Feature::PaymentsDelete => "payments.delete",
            Feature::PaymentsRetry => "payments.retry",
            Feature::JwtVerificationStrategiesView => "jwt_verification_strategies.view",
            Feature::JwtVerificationStrategiesEdit => "jwt_verification_strategies.edit",
            Feature::JwtVerificationStrategiesDelete => "jwt_verification_strategies.delete",
            Feature::StsClientsView => "sts_clients.view",
            Feature::StsClientsEdit => "sts_clients.edit",
            Feature::StsClientsDelete => "sts_clients.delete",
            Feature::StorageAdmin => "storage.admin",
            Feature::PoliciesView => "policies.view",
            Feature::PoliciesEdit => "policies.edit",
            Feature::PoliciesDelete => "policies.delete",
            Feature::ConfigReload => "config.reload",
            Feature::ApiKeysView => "api_keys.view",
            Feature::ApiKeysEdit => "api_keys.edit",
            Feature::ApiKeysDelete => "api_keys.delete",
            Feature::AccessTokensView => "access_tokens.view",
            Feature::AccessTokensEdit => "access_tokens.edit",
            Feature::AccessTokensDelete => "access_tokens.delete",
            Feature::TenantOwnershipManage => "tenant_ownership.manage",
            Feature::CredentialProvidersView => "credential_providers.view",
            Feature::CredentialProvidersEdit => "credential_providers.edit",
            Feature::CredentialProvidersDelete => "credential_providers.delete",
            Feature::CertificatesView => "certificates.view",
            Feature::CertificatesEdit => "certificates.edit",
            Feature::IntegrationsView => "integrations.view",
            Feature::IntegrationsEdit => "integrations.edit",
            Feature::IntegrationsDelete => "integrations.delete",
            Feature::IdentityIssue => "identity.issue",
        }
    }
}

impl RbacConfig {
    /// Check if a user role has permission for a feature
    pub fn has_permission(
        &self,
        user_role: &UserRole,
        feature: &Feature,
    ) -> bool {
        let feature_str = feature.as_str();

        if let Some(required_role_str) = self
            .permissions
            .get(feature_str)
        {
            let required_role = match required_role_str
                .to_lowercase()
                .as_str()
            {
                "administrator" => UserRole::Administrator,
                "poweruser" => UserRole::PowerUser,
                "user" => UserRole::User,
                _ => return false, // Invalid role specified
            };

            // Check if user's role meets or exceeds required role
            match user_role {
                UserRole::Administrator => true, // Administrator has all permissions
                UserRole::PowerUser => {
                    matches!(required_role, UserRole::PowerUser | UserRole::User)
                }
                UserRole::User => matches!(required_role, UserRole::User),
            }
        } else {
            // Feature not in permissions map — deny by default.
            // All legitimate features must be explicitly listed in the
            // permissions map with their minimum required role.
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unrestricted_feature() {
        let config = RbacConfig::default();
        assert!(config.has_permission(&UserRole::User, &Feature::DashboardView));
        assert!(config.has_permission(&UserRole::PowerUser, &Feature::DashboardView));
        assert!(config.has_permission(&UserRole::Administrator, &Feature::DashboardView));
    }

    #[test]
    fn test_admin_only_feature() {
        let mut config = RbacConfig::default();
        config
            .permissions
            .insert("users.edit".to_string(), "administrator".to_string());

        assert!(!config.has_permission(&UserRole::User, &Feature::UsersEdit));
        assert!(!config.has_permission(&UserRole::PowerUser, &Feature::UsersEdit));
        assert!(config.has_permission(&UserRole::Administrator, &Feature::UsersEdit));
    }

    #[test]
    fn test_storage_admin_is_administrator_only() {
        let config = RbacConfig::default();
        assert!(!config.has_permission(&UserRole::User, &Feature::StorageAdmin));
        assert!(!config.has_permission(&UserRole::PowerUser, &Feature::StorageAdmin));
        assert!(config.has_permission(&UserRole::Administrator, &Feature::StorageAdmin));
    }

    /// The built-in default map is the posture an operator gets before they write
    /// their own `rbac.json`, so it must not grant the base role a write or a credential read.
    #[test]
    fn default_base_role_holds_no_write_and_no_credential_read() {
        let config = RbacConfig::default();
        for (feature, role) in &config.permissions {
            let base_role_granted = role.to_lowercase() == "user";
            if !base_role_granted {
                continue;
            }
            assert!(
                !feature.ends_with(".edit") && !feature.ends_with(".delete"),
                "default grants write capability '{feature}' to the base user role"
            );
            assert!(
                !feature.starts_with("secrets.")
                    && !feature.starts_with("certificates.")
                    && !feature.starts_with("api_keys.")
                    && !feature.starts_with("mediators.")
                    && !feature.starts_with("delegation_vault.")
                    && !feature.starts_with("payments."),
                "default grants sensitive read '{feature}' to the base user role"
            );
        }
    }

    #[test]
    fn default_payment_deletion_outranks_payment_reads() {
        let config = RbacConfig::default();
        assert!(!config.has_permission(&UserRole::User, &Feature::PaymentsView));
        assert!(!config.has_permission(&UserRole::User, &Feature::PaymentsRetry));
        assert!(config.has_permission(&UserRole::PowerUser, &Feature::PaymentsView));
        assert!(config.has_permission(&UserRole::PowerUser, &Feature::PaymentsRetry));
        assert!(!config.has_permission(&UserRole::PowerUser, &Feature::PaymentsDelete));
        assert!(config.has_permission(&UserRole::Administrator, &Feature::PaymentsDelete));
    }

    #[test]
    fn test_poweruser_feature() {
        let mut config = RbacConfig::default();
        config
            .permissions
            .insert("surfaces.edit".to_string(), "poweruser".to_string());

        assert!(!config.has_permission(&UserRole::User, &Feature::SurfacesEdit));
        assert!(config.has_permission(&UserRole::PowerUser, &Feature::SurfacesEdit));
        assert!(config.has_permission(&UserRole::Administrator, &Feature::SurfacesEdit));
    }

    /// Regression test for the HIGH-severity findings (H1–H18, except H17 which is intentionally
    /// user-level). Every mutating capability touched by the security review must default to
    /// Administrator so that fresh installs are fail-secure even before rbac.json is customised.
    #[test]
    fn test_high_severity_mutating_features_default_to_admin() {
        let config = RbacConfig::default();
        let admin_only_features = [
            // H1, H6, H16
            Feature::SurfacesEdit,
            Feature::SurfacesDelete,
            // H2, H8
            Feature::GatewaysEdit,
            Feature::GatewaysDelete,
            Feature::PaymentsEdit,
            Feature::PaymentsDelete,
            // H4
            Feature::PoliciesEdit,
            Feature::PoliciesDelete,
            // H5
            Feature::ConfigReload,
            // H7 (also covered by PaymentsEdit/Delete above)
            // H9
            Feature::SecretsEdit,
            Feature::SecretsDelete,
            // Delegation-vault enumerate + mass-revoke of delegated OAuth grants
            Feature::DelegationVaultView,
            Feature::DelegationVaultDelete,
            // H10, H11
            Feature::ApiKeysView,
            Feature::ApiKeysEdit,
            Feature::ApiKeysDelete,
            Feature::TenantOwnershipManage,
            // H12
            Feature::CertificatesEdit,
            // H13
            Feature::TrustRegistriesEdit,
            Feature::TrustRegistriesDelete,
            // H14
            Feature::IntegrationsEdit,
            Feature::IntegrationsDelete,
            // H15, H18
            Feature::IdentityIssue,
            // Trust authorities govern who the gateway trusts
            Feature::AuthoritiesEdit,
            Feature::AuthoritiesDelete,
            // The secret store has no per-record owner, so reads are admin-only too
            Feature::SecretsView,
        ];
        for feature in admin_only_features {
            assert!(
                !config.has_permission(&UserRole::User, &feature),
                "{:?} must NOT be reachable by User role — HIGH severity regression",
                feature
            );
            assert!(
                !config.has_permission(&UserRole::PowerUser, &feature),
                "{:?} must NOT be reachable by PowerUser role — HIGH severity regression",
                feature
            );
            assert!(
                config.has_permission(&UserRole::Administrator, &feature),
                "{:?} must be reachable by Administrator role",
                feature
            );
        }
    }

    #[test]
    fn test_unknown_feature_denied_by_default() {
        let mut config = RbacConfig::default();
        config.permissions.clear();
        assert!(!config.has_permission(&UserRole::User, &Feature::UsersEdit));
        assert!(!config.has_permission(&UserRole::PowerUser, &Feature::UsersEdit));
        assert!(!config.has_permission(&UserRole::Administrator, &Feature::UsersEdit));
    }

    #[test]
    fn test_deserialized_empty_json_uses_secure_defaults() {
        let config: RbacConfig = serde_json::from_str("{}").unwrap();
        assert!(!config.has_permission(&UserRole::User, &Feature::UsersEdit));
        assert!(!config.has_permission(&UserRole::PowerUser, &Feature::UsersEdit));
        assert!(config.has_permission(&UserRole::Administrator, &Feature::UsersEdit));
        assert!(config.has_permission(&UserRole::User, &Feature::DashboardView));
    }

    #[test]
    fn test_deserialized_partial_json_retains_overrides() {
        let json = r#"{"permissions": {"users.edit": "poweruser"}}"#;
        let config: RbacConfig = serde_json::from_str(json).unwrap();
        assert!(config.has_permission(&UserRole::PowerUser, &Feature::UsersEdit));
        assert!(!config.has_permission(&UserRole::User, &Feature::UsersEdit));
    }

    #[test]
    fn test_partial_json_preserves_defaults_for_unlisted_features() {
        let json = r#"{"permissions": {"users.edit": "poweruser"}}"#;
        let config: RbacConfig = serde_json::from_str(json).unwrap();
        assert!(config.has_permission(&UserRole::User, &Feature::DashboardView));
        assert!(config.has_permission(&UserRole::User, &Feature::GatewaysView));
        assert!(config.has_permission(&UserRole::User, &Feature::SurfacesView));
        assert!(!config.has_permission(&UserRole::User, &Feature::SettingsView));
        assert!(config.has_permission(&UserRole::Administrator, &Feature::SettingsView));
    }

    /// Operators who explicitly relax a default-admin feature via rbac.json must still win —
    /// the tightened defaults are a fail-secure floor, not a hard-coded policy.
    #[test]
    fn test_json_override_can_relax_tightened_default() {
        let json = r#"{"permissions": {"secrets.edit": "user"}}"#;
        let config: RbacConfig = serde_json::from_str(json).unwrap();
        assert!(config.has_permission(&UserRole::User, &Feature::SecretsEdit));
    }

    /// Compat: operator-authored `rbac.json` files still using the pre-rename
    /// `departments.*` keys are honoured and normalised to `issuers.*` on load.
    #[test]
    fn rbac_loader_accepts_legacy_departments_keys() {
        let json = r#"{"permissions": {
            "departments.view": "administrator",
            "departments.edit": "administrator",
            "departments.delete": "administrator"
        }}"#;
        let config: RbacConfig = serde_json::from_str(json).expect("legacy rbac.json must parse");
        // Legacy `departments.*` values must be promoted to canonical `issuers.*` keys.
        assert!(!config.has_permission(&UserRole::User, &Feature::IssuersView));
        assert!(!config.has_permission(&UserRole::PowerUser, &Feature::IssuersView));
        assert!(config.has_permission(&UserRole::Administrator, &Feature::IssuersView));
        assert!(config.has_permission(&UserRole::Administrator, &Feature::IssuersEdit));
        assert!(config.has_permission(&UserRole::Administrator, &Feature::IssuersDelete));
    }

    /// Compat: when both legacy and canonical permission keys are present the
    /// canonical value wins (loader ignores the legacy value with a WARN).
    #[test]
    fn rbac_loader_prefers_canonical_when_both_keys_present() {
        let json = r#"{"permissions": {
            "issuers.view": "administrator",
            "departments.view": "user"
        }}"#;
        let config: RbacConfig = serde_json::from_str(json).expect("mixed rbac.json must parse");
        // Canonical value ("administrator") wins over the legacy value ("user").
        assert!(!config.has_permission(&UserRole::User, &Feature::IssuersView));
        assert!(!config.has_permission(&UserRole::PowerUser, &Feature::IssuersView));
        assert!(config.has_permission(&UserRole::Administrator, &Feature::IssuersView));
    }
}
