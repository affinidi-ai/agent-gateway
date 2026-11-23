//! The permission each management route needs from an access token restricted to
//! explicit scopes.
//!
//! An access token with explicit scopes reaches a route only when one of its scopes
//! is a permission the route lists here, or the route is on the middleware's
//! `SCOPED_TOKEN_ALLOWED_ROUTES`. A route missing from both is refused, so a route
//! added without an entry is closed to scoped tokens, not open to them. A session
//! and a token without explicit scopes are not affected.
//!
//! Most entries repeat the permission the route already checks through
//! `require_feature`, an `RbacGuard` or its handler. Routes that check no permission
//! for a session list the permission that names their area, so a scoped token can
//! still reach them; routes with no such permission are in `CLOSED_TO_SCOPED_TOKENS`.

use crate::rbac::Feature::{self, *};
use axum::http::Method;

/// A route, by method and its path as registered (without the prefix the API
/// router is nested at, and with `{placeholders}` for the parts that vary), and the permissions any one of which covers it. `ANY`
/// matches every method.
pub(crate) type RouteScope = (&'static str, &'static str, &'static [Feature]);

pub(crate) const ANY: &str = "ANY";

#[rustfmt::skip]
pub(crate) const ROUTE_SCOPES: &[RouteScope] = &[
    // Dashboard and metrics
    ("GET", "/v1/dashboard/stats", &[DashboardView]),
    ("GET", "/v1/dashboard/delta", &[DashboardView]),
    ("GET", "/v1/dashboard/surface/{channel_config_id}/metrics", &[DashboardView]),
    ("GET", "/v1/dashboard/surface/{channel_config_id}/ucp-operations", &[DashboardView]),
    ("GET", "/v1/dashboard/metrics/hierarchical", &[DashboardView]),
    ("GET", "/v1/dashboard/system-metrics", &[DashboardView]),
    ("GET", "/v1/limits", &[MetricsView]),
    ("GET", "/v1/metrics/otlp-status", &[MetricsView]),
    ("GET", "/v1/metrics/config", &[SettingsEdit]),
    ("PUT", "/v1/metrics/config", &[SettingsEdit]),
    ("POST", "/v1/metrics/test-connection", &[SettingsEdit]),
    ("POST", "/v1/metrics/truncate", &[SettingsEdit]),

    // Settings and configuration
    ("GET", "/v1/settings", &[SettingsView]),
    ("POST", "/v1/settings", &[SettingsEdit]),
    ("DELETE", "/v1/settings", &[SettingsEdit]),
    ("GET", "/v1/settings/audit-events", &[SettingsView]),
    ("GET", "/v1/config/surface-routing", &[SettingsView]),
    ("GET", "/v1/config/x402", &[SettingsView]),
    ("GET", "/v1/config/networking", &[SettingsView]),
    ("GET", "/v1/gateway/config", &[SettingsView]),
    ("POST", "/v1/config/reload", &[ConfigReload]),
    ("POST", "/v1/config/reload/{config_id}", &[ConfigReload]),
    ("POST", "/v1/admin/backup-storage", &[StorageAdmin]),
    ("POST", "/v1/admin/restore-storage", &[StorageAdmin]),
    ("POST", "/v1/debug/export-storage", &[StorageAdmin]),
    ("POST", "/agents-api/v1/sign-jwt", &[SettingsEdit]),

    // Audit and logs
    ("GET", "/v1/audit", &[AuditView]),
    ("GET", "/v1/logs/download", &[AuditView]),
    ("POST", "/v1/logs/truncate", &[SettingsEdit]),
    ("GET", "/v1/delegation-audit", &[AuditView]),

    // Users
    ("GET", "/v1/users", &[UsersView]),
    ("GET", "/v1/users/{user_id}", &[UsersView]),
    ("PUT", "/v1/users/{user_id}", &[UsersEdit]),
    ("DELETE", "/v1/users/{user_id}", &[UsersDelete]),

    // Terms
    ("GET", "/v1/terms", &[TermsView]),
    ("PUT", "/v1/terms/customer/draft", &[TermsEdit]),
    ("POST", "/v1/terms/customer/publish", &[TermsEdit]),
    ("POST", "/v1/terms/customer/deactivate", &[TermsEdit]),

    // Notifications
    ("GET", "/v1/notifications", &[NotificationsView]),
    ("POST", "/v1/notifications", &[NotificationsEdit]),
    ("GET", "/v1/notifications/{id}", &[NotificationsView]),
    ("PUT", "/v1/notifications/{id}", &[NotificationsEdit]),
    ("DELETE", "/v1/notifications/{id}", &[NotificationsDelete]),
    ("GET", "/v1/notifications/unread/count", &[NotificationsView]),
    ("GET", "/v1/notifications/user-welcome-template", &[UsersApprove]),
    ("PUT", "/v1/notifications/user-welcome-template", &[UsersApprove]),
    ("POST", "/v1/notifications/send-welcome", &[UsersApprove]),

    // Identity
    ("POST", "/v1/identity/issue", &[IdentityIssue]),
    ("POST", "/v1/identities", &[IdentityIssue]),
    ("GET", "/v1/identities", &[IdentityIssue]),
    ("GET", "/v1/identities/{id}", &[IdentityIssue]),
    ("DELETE", "/v1/identities/{id}", &[IdentityIssue]),
    ("POST", "/v1/identities/{id}/update", &[IdentityIssue]),
    ("POST", "/v1/identities/{id}/rotate-keys", &[IdentityIssue]),
    ("POST", "/v1/identities/{id}/transfer", &[IdentityIssue]),
    ("GET", "/v1/identities/{id}/history", &[IdentityIssue]),
    ("PUT", "/v1/identities/{id}/policy", &[IdentityIssue]),
    ("GET", "/v1/identities/{id}/policy", &[IdentityIssue]),
    ("POST", "/v1/vault/identity/generate", &[IdentityIssue]),

    // Surfaces, agents and templates
    ("GET", "/v1/surfaces", &[SurfacesView]),
    ("POST", "/v1/surfaces", &[SurfacesEdit]),
    ("POST", "/v1/surfaces/validate-policy", &[SurfacesEdit]),
    ("GET", "/v1/surfaces/{surface_id}", &[SurfacesView]),
    ("PUT", "/v1/surfaces/{surface_id}", &[SurfacesEdit]),
    ("PATCH", "/v1/surfaces/{surface_id}", &[SurfacesEdit]),
    ("DELETE", "/v1/surfaces/{surface_id}", &[SurfacesDelete]),
    ("GET", "/v1/surfaces/{surface_id}/trust-recorder-status", &[SurfacesView]),
    ("GET", "/v1/surfaces/{surface_id}/agent-card", &[SurfacesView]),
    ("POST", "/v1/surfaces/{surface_id}/agent-card/refresh", &[SurfacesEdit]),
    ("POST", "/v1/surfaces/{surface_id}/variants", &[SurfacesEdit]),
    ("PUT", "/v1/surfaces/{surface_id}/variants/{variant_id}", &[SurfacesEdit]),
    ("PATCH", "/v1/surfaces/{surface_id}/variants/{variant_id}", &[SurfacesEdit]),
    ("DELETE", "/v1/surfaces/{surface_id}/variants/{variant_id}", &[SurfacesDelete]),
    ("POST", "/v1/surfaces/{surface_id}/variants/{variant_id}/promote-to-default", &[SurfacesEdit]),
    ("GET", "/v1/surfaces/{surface_id}/variants/{alias}/resolved", &[SurfacesView]),
    ("GET", "/v1/agents", &[SurfacesView]),
    ("GET", "/v1/agents/{id}", &[SurfacesView]),
    ("GET", "/v1/agents/{id}/agent-card", &[SurfacesView]),
    ("GET", "/v1/surface-templates", &[SurfacesView]),
    ("POST", "/v1/surface-templates", &[SurfacesEdit]),
    ("POST", "/v1/surface-templates/import", &[SurfacesEdit]),
    ("GET", "/v1/surface-templates/{template_id}", &[SurfacesView]),
    ("PUT", "/v1/surface-templates/{template_id}", &[SurfacesEdit]),
    ("DELETE", "/v1/surface-templates/{template_id}", &[SurfacesDelete]),
    ("GET", "/v1/surface-templates/{template_id}/export", &[SurfacesView]),
    ("POST", "/v1/onboard/create-temp-surface", &[SurfacesEdit]),
    ("DELETE", "/v1/onboard/delete-temp-channel/{config_id}", &[SurfacesDelete]),
    ("GET", "/v1/trust-check/predefined-queries", &[SurfacesView]),

    // Policies and tenant ownership
    ("GET", "/v1/policy-definitions", &[PoliciesView]),
    ("POST", "/v1/policy-definitions", &[PoliciesEdit]),
    ("GET", "/v1/policy-definitions/{policy_id}", &[PoliciesView]),
    ("PUT", "/v1/policy-definitions/{policy_id}", &[PoliciesEdit]),
    ("DELETE", "/v1/policy-definitions/{policy_id}", &[PoliciesDelete]),
    ("GET", "/v1/policy-definitions/{policy_id}/versions", &[PoliciesView]),
    ("GET", "/v1/policy-definitions/{policy_id}/impact", &[PoliciesView]),
    ("POST", "/v1/policy-definitions/{policy_id}/simulate", &[PoliciesEdit]),
    ("GET", "/v1/policy-assignments", &[PoliciesView]),
    ("PUT", "/v1/policy-assignments", &[PoliciesEdit]),
    ("GET", "/v1/tenant-ownership/{kind}/{id}/impact", &[TenantOwnershipManage]),
    ("PUT", "/v1/tenant-ownership/{kind}/{id}", &[TenantOwnershipManage]),

    // Gateways and payment gateways
    ("GET", "/v1/gateways", &[GatewaysView]),
    ("POST", "/v1/gateways", &[GatewaysEdit]),
    ("POST", "/v1/gateways/connect-via-oob", &[GatewaysEdit]),
    ("GET", "/v1/gateways/{id}", &[GatewaysView]),
    ("PUT", "/v1/gateways/{id}", &[GatewaysEdit]),
    ("DELETE", "/v1/gateways/{id}", &[GatewaysDelete]),
    ("POST", "/v1/gateways/{id}/payment-role", &[GatewaysEdit]),
    ("GET", "/v1/gateways/{id}/policy", &[GatewaysView]),
    ("PUT", "/v1/gateways/{id}/policy", &[GatewaysEdit]),
    ("POST", "/v1/gateways/{id}/ping", &[GatewaysEdit]),
    ("POST", "/v1/gateways/{id}/issuer", &[GatewaysEdit]),
    ("DELETE", "/v1/gateways/{id}/issuer", &[GatewaysEdit]),
    ("POST", "/v1/gateways/{id}/trusted-issuers", &[GatewaysEdit]),
    ("DELETE", "/v1/gateways/{id}/trusted-issuers/{issuer_did}", &[GatewaysEdit]),
    ("GET", "/v1/gateways/{id}/surfaces", &[GatewaysView]),
    ("PUT", "/v1/gateways/{id}/exposed-surfaces", &[GatewaysEdit]),
    ("POST", "/v1/gateways/refresh-surfaces", &[GatewaysEdit]),
    ("POST", "/v1/gateways/{id}/approve", &[GatewaysEdit]),
    ("GET", "/v1/gateways/{gateway_id}/connection-points", &[GatewaysView]),
    ("GET", "/v1/gateways/payment-logos/{sha256}", &[PaymentGatewaysView]),
    ("GET", "/v1/gateways/payment-providers", &[PaymentGatewaysView]),
    ("GET", "/v1/payment-gateways", &[PaymentGatewaysView]),
    ("POST", "/v1/payment-gateways/connect-via-oob", &[PaymentGatewaysEdit]),
    ("GET", "/v1/payment-gateways/{id}", &[PaymentGatewaysView]),
    ("PUT", "/v1/payment-gateways/{id}", &[PaymentGatewaysEdit]),
    ("DELETE", "/v1/payment-gateways/{id}", &[PaymentGatewaysDelete]),
    ("POST", "/v1/payment-gateways/{id}/ping", &[PaymentGatewaysEdit]),
    ("GET", "/v1/payment-gateways/{id}/surfaces", &[PaymentGatewaysView]),
    ("GET", "/v1/payment-gateways/{id}/surfaces/{surface_id}/payment-manifest", &[PaymentGatewaysView]),
    ("GET", "/v1/payment-gateways/{id}/info", &[PaymentGatewaysView]),

    // Connection points
    ("GET", "/v1/connection-points", &[GatewaysView]),
    ("POST", "/v1/connection-points", &[GatewaysEdit]),
    ("GET", "/v1/connection-points/{id}", &[GatewaysView]),
    ("PUT", "/v1/connection-points/{id}", &[GatewaysEdit]),
    ("DELETE", "/v1/connection-points/{id}", &[GatewaysDelete]),
    ("POST", "/v1/connection-points/{id}/use", &[GatewaysEdit]),
    ("PUT", "/v1/connection-points/{id}/exposed-surfaces", &[GatewaysEdit]),
    ("GET", "/v1/connection-points/{id}/messages", &[GatewaysView]),
    ("GET", "/v1/connection-points/{id}/messages/{message_id}", &[GatewaysView]),
    ("POST", "/v1/connection-points/{id}/messages/{message_id}/read", &[GatewaysEdit]),
    ("DELETE", "/v1/connection-points/{id}/messages/{message_id}", &[GatewaysEdit]),
    ("GET", "/v1/connection-points/{id}/messages/unread-count", &[GatewaysView]),
    ("GET", "/v1/connection-points/{id}/metrics", &[GatewaysView]),
    ("POST", "/v1/connection-points/{id}/reconnect", &[GatewaysEdit]),

    // Mediators
    ("GET", "/v1/mediators", &[MediatorsView]),
    ("POST", "/v1/mediators", &[MediatorsEdit]),
    ("GET", "/v1/mediators/compatible", &[MediatorsView]),
    ("POST", "/v1/mediators/check-auth", &[MediatorsEdit]),
    ("GET", "/v1/mediators/{id}", &[MediatorsView]),
    ("PUT", "/v1/mediators/{id}", &[MediatorsEdit]),
    ("DELETE", "/v1/mediators/{id}", &[MediatorsDelete]),
    ("POST", "/v1/mediators/{id}/trust-ping", &[MediatorsEdit]),

    // Issuers (the legacy department routes redirect to them)
    ("GET", "/v1/issuers", &[IssuersView]),
    ("POST", "/v1/issuers", &[IssuersEdit]),
    ("GET", "/v1/issuers/{id}", &[IssuersView]),
    ("PUT", "/v1/issuers/{id}", &[IssuersEdit]),
    ("DELETE", "/v1/issuers/{id}", &[IssuersDelete]),
    ("POST", "/v1/issuers/{id}/register-trust-registry", &[IssuersEdit]),
    ("POST", "/v1/admin/issuers/migrate-to-webvh", &[IssuersEdit]),
    (ANY, "/v1/departments", &[IssuersView, IssuersEdit, IssuersDelete]),
    (ANY, "/v1/departments/{id}", &[IssuersView, IssuersEdit, IssuersDelete]),
    (ANY, "/v1/departments/{id}/register-trust-registry", &[IssuersEdit]),
    (ANY, "/v1/admin/departments/migrate-to-webvh", &[IssuersEdit]),

    // Authorities
    ("GET", "/v1/authorities", &[AuthoritiesView]),
    ("POST", "/v1/authorities", &[AuthoritiesEdit]),
    ("GET", "/v1/authorities/{id}", &[AuthoritiesView]),
    ("PUT", "/v1/authorities/{id}", &[AuthoritiesEdit]),
    ("DELETE", "/v1/authorities/{id}", &[AuthoritiesDelete]),

    // MCP and A2A proxies
    ("GET", "/v1/mcp-proxies", &[McpProxiesView]),
    ("POST", "/v1/mcp-proxies", &[McpProxiesEdit]),
    ("POST", "/v1/mcp-proxies/validate", &[McpProxiesEdit]),
    ("GET", "/v1/mcp-proxies/{id}", &[McpProxiesView]),
    ("PUT", "/v1/mcp-proxies/{id}", &[McpProxiesEdit]),
    ("DELETE", "/v1/mcp-proxies/{id}", &[McpProxiesDelete]),
    ("POST", "/v1/mcp-proxies/discover-tools", &[McpProxiesEdit]),
    ("GET", "/v1/a2a-proxies", &[A2aProxiesView]),
    ("POST", "/v1/a2a-proxies", &[A2aProxiesEdit]),
    ("GET", "/v1/a2a-proxies/{id}", &[A2aProxiesView]),
    ("PUT", "/v1/a2a-proxies/{id}", &[A2aProxiesEdit]),
    ("DELETE", "/v1/a2a-proxies/{id}", &[A2aProxiesDelete]),

    // Trust registries
    ("GET", "/trust-registries/{tr_id}/did.json", &[TrustRegistriesView]),
    ("GET", "/trust-registries/{tr_id}/did.jsonl", &[TrustRegistriesView]),
    ("GET", "/trust-registries/{tr_id}/did-witness.json", &[TrustRegistriesView]),
    ("GET", "/v1/trust-registries", &[TrustRegistriesView]),
    ("POST", "/v1/trust-registries", &[TrustRegistriesEdit]),
    ("GET", "/v1/trust-registries/{id}", &[TrustRegistriesView]),
    ("PUT", "/v1/trust-registries/{id}", &[TrustRegistriesEdit]),
    ("DELETE", "/v1/trust-registries/{id}", &[TrustRegistriesDelete]),
    ("POST", "/v1/trust-registries/{id}/list-records", &[TrustRegistriesView]),
    ("POST", "/v1/trust-registries/{id}/reconnect", &[TrustRegistriesEdit]),

    // STS clients and JWT verification strategies
    ("POST", "/v1/sts/clients", &[StsClientsEdit]),
    ("GET", "/v1/sts/clients", &[StsClientsView]),
    ("GET", "/v1/sts/clients/{id}", &[StsClientsView]),
    ("PUT", "/v1/sts/clients/{id}", &[StsClientsEdit]),
    ("DELETE", "/v1/sts/clients/{id}", &[StsClientsDelete]),
    ("POST", "/v1/jwt-verification-strategies/validate-jwks-uri", &[JwtVerificationStrategiesEdit]),
    ("POST", "/v1/jwt-verification-strategies", &[JwtVerificationStrategiesEdit]),
    ("GET", "/v1/jwt-verification-strategies", &[JwtVerificationStrategiesView]),
    ("GET", "/v1/jwt-verification-strategies/{id}", &[JwtVerificationStrategiesView]),
    ("PUT", "/v1/jwt-verification-strategies/{id}", &[JwtVerificationStrategiesEdit]),
    ("DELETE", "/v1/jwt-verification-strategies/{id}", &[JwtVerificationStrategiesDelete]),

    // Integrations
    ("GET", "/v1/integrations", &[IntegrationsView]),
    ("POST", "/v1/integrations", &[IntegrationsEdit]),
    ("GET", "/v1/integrations/{id}", &[IntegrationsView]),
    ("PUT", "/v1/integrations/{id}", &[IntegrationsEdit]),
    ("DELETE", "/v1/integrations/{id}", &[IntegrationsDelete]),
    ("POST", "/v1/integrations/{id}/test", &[IntegrationsEdit]),
    ("POST", "/v1/integrations/test", &[IntegrationsEdit]),
    ("POST", "/v1/integrations/endpoints/{id}/test", &[IntegrationsEdit]),
    ("GET", "/v1/integrations/catalog", &[IntegrationsView]),
    ("GET", "/v1/integrations/endpoints", &[IntegrationsView]),
    ("POST", "/v1/integrations/endpoints", &[IntegrationsEdit]),
    ("GET", "/v1/integrations/endpoints/{id}", &[IntegrationsView]),
    ("PUT", "/v1/integrations/endpoints/{id}", &[IntegrationsEdit]),
    ("DELETE", "/v1/integrations/endpoints/{id}", &[IntegrationsDelete]),
    ("GET", "/v1/integrations/event-sets", &[IntegrationsView]),
    ("POST", "/v1/integrations/event-sets", &[IntegrationsEdit]),
    ("GET", "/v1/integrations/event-sets/{id}", &[IntegrationsView]),
    ("PUT", "/v1/integrations/event-sets/{id}", &[IntegrationsEdit]),
    ("DELETE", "/v1/integrations/event-sets/{id}", &[IntegrationsDelete]),

    // Payments
    ("GET", "/admin/x402/payments/all", &[PaymentsView]),
    ("GET", "/admin/x402/payments/{payment_id}", &[PaymentsView]),
    ("GET", "/admin/x402/payments", &[PaymentsView]),
    ("GET", "/admin/x402/stats", &[PaymentsView]),
    ("GET", "/admin/x402/sync-status", &[PaymentsView]),
    ("GET", "/admin/x402/transactions/{transaction_id}", &[PaymentsView]),
    ("DELETE", "/admin/x402/transactions/{transaction_id}", &[PaymentsDelete]),
    ("GET", "/admin/x402/transactions", &[PaymentsView]),
    ("DELETE", "/admin/x402/verifications/{verification_id}", &[PaymentsDelete]),
    ("GET", "/admin/x402/verifications", &[PaymentsView]),
    ("DELETE", "/admin/x402/settlements/{settlement_id}", &[PaymentsDelete]),
    ("GET", "/admin/x402/settlements", &[PaymentsView]),
    ("GET", "/admin/mpp/transactions", &[PaymentsView]),
    ("GET", "/admin/mpp/transactions/{transaction_id}", &[PaymentsView]),
    ("GET", "/admin/payments", &[PaymentsView]),
    ("GET", "/admin/payments/audit", &[PaymentsView]),
    ("GET", "/admin/payments/summary", &[PaymentsView]),
    ("GET", "/admin/payments/breakers/{payment_gateway_id}", &[PaymentsView]),
    ("GET", "/admin/payments/{id}", &[PaymentsView]),

    // Secrets, certificates, API keys and access tokens
    ("GET", "/v1/secrets", &[SecretsView]),
    ("GET", "/v1/secrets/", &[SecretsView]),
    ("POST", "/v1/secrets/new", &[SecretsEdit]),
    ("GET", "/v1/secrets/{id}", &[SecretsView]),
    ("PUT", "/v1/secrets/{id}", &[SecretsEdit]),
    ("DELETE", "/v1/secrets/{id}", &[SecretsDelete]),
    ("GET", "/v1/secrets/tag/{tag}", &[SecretsView]),
    ("GET", "/v1/certificates", &[CertificatesView]),
    ("POST", "/v1/certificates", &[CertificatesEdit]),
    ("GET", "/v1/certificates/", &[CertificatesView]),
    ("POST", "/v1/certificates/", &[CertificatesEdit]),
    ("GET", "/v1/certificates/{id}", &[CertificatesView]),
    ("PUT", "/v1/certificates/{id}", &[CertificatesEdit]),
    ("DELETE", "/v1/certificates/{id}", &[CertificatesEdit]),
    ("GET", "/v1/api-keys", &[ApiKeysView]),
    ("GET", "/v1/api-keys/{agent_id}", &[ApiKeysView]),
    ("POST", "/v1/api-keys/{agent_id}", &[ApiKeysEdit]),
    ("GET", "/v1/api-keys/{agent_id}/{key_id}", &[ApiKeysView]),
    ("POST", "/v1/api-keys/{agent_id}/{key_id}/revoke", &[ApiKeysEdit]),
    ("POST", "/v1/api-keys/{agent_id}/{key_id}/rotate", &[ApiKeysEdit]),
    ("DELETE", "/v1/api-keys/{agent_id}/{key_id}", &[ApiKeysDelete]),
    ("GET", "/v1/access-tokens", &[AccessTokensView]),
    ("POST", "/v1/access-tokens", &[AccessTokensEdit]),
    ("GET", "/v1/access-tokens/{id}", &[AccessTokensView]),
    ("PUT", "/v1/access-tokens/{id}", &[AccessTokensEdit]),
    ("DELETE", "/v1/access-tokens/{id}", &[AccessTokensDelete]),
    ("POST", "/v1/access-tokens/{id}/rotate", &[AccessTokensEdit]),

    // Credential providers and the delegation vault
    ("POST", "/v1/credential-providers/validate", &[CredentialProvidersEdit]),
    ("POST", "/v1/credential-providers", &[CredentialProvidersEdit]),
    ("GET", "/v1/credential-providers", &[CredentialProvidersView]),
    ("GET", "/v1/credential-providers/{id}", &[CredentialProvidersView]),
    ("PUT", "/v1/credential-providers/{id}", &[CredentialProvidersEdit]),
    ("DELETE", "/v1/credential-providers/{id}", &[CredentialProvidersDelete]),
    ("POST", "/v1/credential-providers/{id}/deactivate", &[CredentialProvidersEdit]),
    ("POST", "/v1/credential-providers/{id}/activate", &[CredentialProvidersEdit]),
    ("GET", "/v1/credential-providers/{id}/consent-impact", &[CredentialProvidersEdit]),
    ("GET", "/v1/delegation-vault", &[DelegationVaultView]),
    ("GET", "/v1/delegation-vault/{id}", &[DelegationVaultView]),
    ("DELETE", "/v1/delegation-vault/{id}", &[DelegationVaultDelete]),
    ("PUT", "/v1/delegation-vault/{id}/consent-limit", &[DelegationVaultDelete]),
    ("DELETE", "/v1/delegation-vault/by-user/{user_hash}", &[DelegationVaultDelete]),
    ("POST", "/v1/delegation-vault/connects", &[DelegationVaultConnect]),
    ("POST", "/v1/delegation-vault/connects/{connect_id}/complete", &[DelegationVaultConnect]),
    ("GET", "/v1/delegation-vault/grants", &[DelegationVaultConnect]),
    ("DELETE", "/v1/delegation-vault/grants", &[DelegationVaultDelete]),
    ("DELETE", "/v1/delegation-vault/grants/{grant_id}", &[DelegationVaultDelete]),
];

/// Routes no scope covers: each checks no permission for a session (they serve the
/// caller's own account, public data or a DID check) and no permission names their
/// area, so a token with explicit scopes is always refused on them.
#[rustfmt::skip]
pub(crate) const CLOSED_TO_SCOPED_TOKENS: &[(&str, &str)] = &[
    ("GET", "/v1/identity/did-document"),
    ("GET", "/v1/identities/by-hash/{identity_hash}/rotations"),
    ("GET", "/v1/profile"),
    ("PUT", "/v1/profile"),
    ("POST", "/v1/profile/avatar"),
    ("GET", "/v1/user-settings"),
    ("POST", "/v1/user-settings"),
    ("DELETE", "/v1/user-settings"),
    ("GET", "/v1/user-settings/overrides"),
    ("GET", "/v1/terms/status"),
    ("POST", "/v1/terms/acceptances"),
    ("POST", "/v1/verify/{did}"),
];

/// The route a request matched, by its path as registered and without the prefix
/// the API router is nested at: `matched` is that path as axum reports it, with the
/// prefix, `original_path` the path the client sent and `routed_path` the path the
/// router saw, from which a nesting router has removed its prefix. Routers mounted
/// with a literal `/api` prefix lose it too.
pub fn registered_route<'a>(
    matched: &'a str,
    original_path: &str,
    routed_path: &str,
) -> &'a str {
    let nest_prefix = original_path
        .strip_suffix(routed_path)
        .unwrap_or("");
    let route = matched
        .strip_prefix(nest_prefix)
        .unwrap_or(matched);
    match route.strip_prefix("/api") {
        Some(rest) if rest.starts_with('/') => rest,
        _ => route,
    }
}

/// The permissions any one of which covers a `method` request to the route
/// `route`, or `None` when no entry names the route.
pub fn route_permissions(
    method: &Method,
    route: &str,
) -> Option<&'static [Feature]> {
    ROUTE_SCOPES
        .iter()
        .find(|(route_method, path, _)| *path == route && (*route_method == ANY || *route_method == method.as_str()))
        .map(|(_, _, permissions)| *permissions)
}

/// What an access token with explicit scopes gets on a route.
#[derive(Debug, PartialEq, Eq)]
pub enum ScopedAccess {
    Allowed,
    /// None of its scopes covers the route: `403`.
    Refused,
    /// The route is listed but not for this method: `405`, as for any caller.
    MethodNotAllowed,
}

/// What an access token with explicit `scopes` gets on a `method` request to
/// `route`. `HEAD` is answered like `GET`, as axum does. A route that is neither
/// covered nor listed for any method is refused.
pub fn scoped_access(
    scopes: &[String],
    method: &Method,
    route: &str,
) -> ScopedAccess {
    let method = if method == Method::HEAD {
        &Method::GET
    } else {
        method
    };
    if CLOSED_TO_SCOPED_TOKENS.contains(&(method.as_str(), route)) {
        return ScopedAccess::Refused;
    }
    match route_permissions(method, route) {
        Some(permissions)
            if permissions
                .iter()
                .any(|permission| crate::auth_manager::pat::scope_grants(scopes, permission)) =>
        {
            ScopedAccess::Allowed
        }
        Some(_) => ScopedAccess::Refused,
        None if ROUTE_SCOPES
            .iter()
            .any(|(_, path, _)| *path == route)
            || CLOSED_TO_SCOPED_TOKENS
                .iter()
                .any(|(_, path)| *path == route) =>
        {
            ScopedAccess::MethodNotAllowed
        }
        None => ScopedAccess::Refused,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scopes(values: &[&str]) -> Vec<String> {
        values
            .iter()
            .map(|value| (*value).to_string())
            .collect()
    }

    fn access(
        granted: &[&str],
        method: Method,
        route: &str,
    ) -> ScopedAccess {
        scoped_access(&scopes(granted), &method, route)
    }

    #[test]
    fn a_scope_naming_the_route_permission_covers_it() {
        assert_eq!(access(&["settings.view"], Method::GET, "/v1/settings"), ScopedAccess::Allowed);
        assert_eq!(access(&["surfaces.edit"], Method::POST, "/v1/surfaces/validate-policy"), ScopedAccess::Allowed);
    }

    #[test]
    fn a_scope_naming_another_permission_does_not_cover_the_route() {
        assert_eq!(access(&["surfaces.view"], Method::GET, "/v1/settings"), ScopedAccess::Refused);
        assert_eq!(access(&["surfaces.edit"], Method::GET, "/v1/surfaces"), ScopedAccess::Refused);
        assert_eq!(access(&[], Method::GET, "/v1/settings"), ScopedAccess::Refused);
    }

    #[test]
    fn the_method_selects_the_permission() {
        assert_eq!(route_permissions(&Method::GET, "/v1/settings"), Some(&[Feature::SettingsView][..]));
        assert_eq!(route_permissions(&Method::POST, "/v1/settings"), Some(&[Feature::SettingsEdit][..]));
        assert_eq!(route_permissions(&Method::PATCH, "/v1/settings"), None);
    }

    #[test]
    fn head_is_answered_like_get() {
        assert_eq!(access(&["settings.view"], Method::HEAD, "/v1/settings"), ScopedAccess::Allowed);
        assert_eq!(access(&["surfaces.view"], Method::HEAD, "/v1/settings"), ScopedAccess::Refused);
        assert_eq!(access(&["settings.view"], Method::HEAD, "/v1/profile"), ScopedAccess::Refused);
    }

    #[test]
    fn a_method_the_route_does_not_list_is_not_allowed() {
        assert_eq!(access(&["settings.view"], Method::PATCH, "/v1/settings"), ScopedAccess::MethodNotAllowed);
        assert_eq!(access(&[], Method::PUT, "/v1/settings/audit-events"), ScopedAccess::MethodNotAllowed);
    }

    #[test]
    fn a_method_a_closed_route_does_not_serve_is_not_allowed() {
        assert_eq!(access(&["settings.view"], Method::POST, "/v1/profile"), ScopedAccess::MethodNotAllowed);
        assert_eq!(access(&["settings.edit"], Method::PATCH, "/v1/user-settings"), ScopedAccess::MethodNotAllowed);
        for method in [Method::GET, Method::PUT, Method::HEAD] {
            assert_eq!(access(&["settings.view"], method, "/v1/profile"), ScopedAccess::Refused);
        }
    }

    #[test]
    fn an_any_method_route_matches_every_method() {
        for method in [Method::GET, Method::POST, Method::DELETE] {
            assert_eq!(access(&["issuers.view"], method, "/v1/departments"), ScopedAccess::Allowed);
        }
    }

    #[test]
    fn a_route_without_an_entry_is_refused() {
        assert_eq!(route_permissions(&Method::GET, "/v1/profile"), None);
        assert_eq!(access(&["settings.view", "users.view"], Method::GET, "/v1/profile"), ScopedAccess::Refused);
        assert_eq!(access(&["settings.view"], Method::GET, "/v1/unlisted"), ScopedAccess::Refused);
    }

    #[test]
    fn the_registered_route_drops_the_prefix_the_api_router_is_nested_at() {
        assert_eq!(
            registered_route("/api/v1/surfaces/{surface_id}", "/api/v1/surfaces/s1", "/v1/surfaces/s1"),
            "/v1/surfaces/{surface_id}"
        );
        assert_eq!(registered_route("/gw/v1/settings", "/gw/v1/settings", "/v1/settings"), "/v1/settings");
        assert_eq!(registered_route("/v1/settings", "/v1/settings", "/v1/settings"), "/v1/settings");
    }

    #[test]
    fn the_registered_route_drops_a_literal_api_prefix() {
        assert_eq!(
            registered_route("/api/v1/secrets/{id}", "/api/v1/secrets/s1", "/api/v1/secrets/s1"),
            "/v1/secrets/{id}"
        );
        assert_eq!(
            registered_route("/apix/v1/settings", "/apix/v1/settings", "/apix/v1/settings"),
            "/apix/v1/settings"
        );
    }

    #[test]
    fn every_entry_is_listed_once() {
        let mut seen = std::collections::HashSet::new();
        for (method, path, permissions) in ROUTE_SCOPES {
            assert!(seen.insert((*method, *path)), "{method} {path} is listed twice");
            assert!(!permissions.is_empty(), "{method} {path} lists no permission");
        }
    }

    #[test]
    fn no_scope_covers_a_closed_route() {
        let every_permission =
            scopes(&["settings.view", "settings.edit", "users.view", "users.edit", "identity.issue"]);
        for (method, path) in CLOSED_TO_SCOPED_TOKENS {
            let method = Method::from_bytes(method.as_bytes()).unwrap();
            assert_eq!(route_permissions(&method, path), None, "{method} {path} is also in ROUTE_SCOPES");
            assert_eq!(scoped_access(&every_permission, &method, path), ScopedAccess::Refused, "{method} {path}");
        }
    }
}
