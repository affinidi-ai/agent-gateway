use std::fmt;

use serde::{Deserialize, Serialize};

use crate::auth_manager::pat::{PatResourceScope, scope_allows};
use crate::auth_manager::resource_scope::TenantSelector;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PatTenantContext {
    pub token_id: String,
    pub tenant_id: String,
}

/// Tenancy configuration (`tenancy` in bootstrap config).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct TenancyConfig {
    /// Opt-in assertion that an edge-authenticated trusted proxy sets/strips the
    /// PAT tenant-selector header. Absent by default (OSS / standalone), which
    /// makes broad tenant selectors fail closed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trusted_tenant_header: Option<TrustedTenantHeader>,
}

/// Declares that a trusted, edge-authenticated proxy owns a specific tenant
/// header — it strips any caller-supplied value and sets the tenant from
/// authenticated upstream context (e.g. mTLS / network ACL). Only when this is
/// configured (and its assertion is affirmed) may a broad/multi-valued tenant
/// selector be honored, because the header is then trustworthy input rather
/// than bearer-chosen.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TrustedTenantHeader {
    /// Name of the header the trusted edge sets/strips (matched
    /// case-insensitively against the PAT tenant-selector header).
    pub header: String,
    /// Operator's explicit assertion that the edge strips caller-supplied
    /// values of `header` before the request reaches the gateway. Must be
    /// `true` for the trusted-edge exemption to take effect; header presence
    /// alone is never sufficient.
    #[serde(default)]
    pub edge_strips_client_values: bool,
}

impl TrustedTenantHeader {
    /// Whether this trusted-edge declaration covers `tenant_header_name` and its
    /// header-stripping assertion is affirmed.
    pub fn covers(
        &self,
        tenant_header_name: &str,
    ) -> bool {
        self.edge_strips_client_values
            && self
                .header
                .eq_ignore_ascii_case(tenant_header_name)
    }
}

/// Decide whether a request whose tenant would be derived from a caller-supplied
/// header may proceed (the tenant-header fail-closed policy).
///
/// - An **exact** selector is always permitted: the anchored header regex admits
///   only one value, so the tenant is effectively bound to the token.
/// - A **broad** selector is permitted only when a trusted edge is configured
///   for that exact header and affirms it strips caller-supplied values.
pub fn header_derived_tenant_permitted(
    selector: &TenantSelector,
    trusted_edge: Option<&TrustedTenantHeader>,
) -> bool {
    if !selector.broad {
        return true;
    }
    trusted_edge.is_some_and(|edge| edge.covers(&selector.header_name))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResourceKind {
    Secrets,
    Certificates,
    ApiKeys,
    Surfaces,
    Gateways,
    ConnectionPoints,
    Mediators,
    McpProxies,
    A2aProxies,
    TrustRegistries,
    Issuers,
    Authorities,
    Integrations,
    PolicyDefinitions,
    SurfaceTemplates,
    CredentialProviders,
    JwtVerificationStrategies,
    StsClients,
}

impl ResourceKind {
    pub fn from_path_family(family: &str) -> Option<Self> {
        match family {
            "secrets" => Some(Self::Secrets),
            "certificates" => Some(Self::Certificates),
            "api-keys" => Some(Self::ApiKeys),
            "surfaces" => Some(Self::Surfaces),
            "gateways" => Some(Self::Gateways),
            "connection-points" => Some(Self::ConnectionPoints),
            "mediators" => Some(Self::Mediators),
            "mcp-proxies" => Some(Self::McpProxies),
            "a2a-proxies" => Some(Self::A2aProxies),
            "trust-registries" => Some(Self::TrustRegistries),
            "issuers" | "departments" => Some(Self::Issuers),
            "authorities" => Some(Self::Authorities),
            "integrations" => Some(Self::Integrations),
            "policy-definitions" => Some(Self::PolicyDefinitions),
            "surface-templates" => Some(Self::SurfaceTemplates),
            "credential-providers" => Some(Self::CredentialProviders),
            "jwt-verification-strategies" => Some(Self::JwtVerificationStrategies),
            "sts-clients" => Some(Self::StsClients),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Secrets => "secrets",
            Self::Certificates => "certificates",
            Self::ApiKeys => "api-keys",
            Self::Surfaces => "surfaces",
            Self::Gateways => "gateways",
            Self::ConnectionPoints => "connection-points",
            Self::Mediators => "mediators",
            Self::McpProxies => "mcp-proxies",
            Self::A2aProxies => "a2a-proxies",
            Self::TrustRegistries => "trust-registries",
            Self::Issuers => "issuers",
            Self::Authorities => "authorities",
            Self::Integrations => "integrations",
            Self::PolicyDefinitions => "policy-definitions",
            Self::SurfaceTemplates => "surface-templates",
            Self::CredentialProviders => "credential-providers",
            Self::JwtVerificationStrategies => "jwt-verification-strategies",
            Self::StsClients => "sts-clients",
        }
    }
}

impl fmt::Display for ResourceKind {
    fn fmt(
        &self,
        formatter: &mut fmt::Formatter<'_>,
    ) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

pub fn validate_tenant_id(tenant_id: &str) -> Result<(), &'static str> {
    if tenant_id.is_empty() || tenant_id.len() > 128 {
        return Err("tenant id must contain between 1 and 128 characters");
    }
    if !tenant_id
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
    {
        return Err("tenant id contains unsupported characters");
    }
    Ok(())
}

pub fn canonical_resource_target(
    tenant_id: &str,
    kind: ResourceKind,
    resource_id: &str,
) -> String {
    format!("TENANT:{tenant_id}:{}:{resource_id}", kind.as_str())
}

/// May this caller *see* the resource, or point something of their own at it?
///
/// Deliberately permissive about untenanted resources: one with no `tenant_id`
/// was created by an operator through the dashboard, and referencing those is a
/// feature — a tenant surface may enforce a policy the operator published.
///
/// Read access is not write access. See [`can_mutate`].
pub fn can_access(
    resource_tenant_id: Option<&str>,
    context: Option<&PatTenantContext>,
) -> bool {
    context.is_none_or(|context| resource_tenant_id.is_none() || resource_tenant_id == Some(context.tenant_id.as_str()))
}

/// May this caller change or delete the resource? A tenant context may mutate
/// only resources carrying its own tenant id; no context means appliance-wide.
pub fn can_mutate(
    resource_tenant_id: Option<&str>,
    context: Option<&PatTenantContext>,
) -> bool {
    match context {
        None => true,
        Some(context) => resource_tenant_id == Some(context.tenant_id.as_str()),
    }
}

pub fn can_reference(
    owner_tenant_id: Option<&str>,
    referenced_tenant_id: Option<&str>,
) -> bool {
    match owner_tenant_id {
        Some(owner) => referenced_tenant_id.is_none_or(|referenced| referenced == owner),
        None => referenced_tenant_id.is_none(),
    }
}

pub fn scope_allows_resource(
    scope: Option<&PatResourceScope>,
    context: Option<&PatTenantContext>,
    kind: ResourceKind,
    resource_id: &str,
) -> bool {
    let canonical;
    let target = if let Some(context) = context {
        canonical = canonical_resource_target(&context.tenant_id, kind, resource_id);
        canonical.as_str()
    } else {
        resource_id
    };
    scope_allows(scope, target)
}

pub fn tenant_for_create(
    requested_tenant_id: Option<String>,
    pat_authenticated: bool,
    context: Option<&PatTenantContext>,
) -> Result<Option<String>, &'static str> {
    if let Some(context) = context {
        if requested_tenant_id
            .as_deref()
            .is_some_and(|requested| requested != context.tenant_id)
        {
            return Err("tenant_id conflicts with the PAT tenant context");
        }
        return Ok(Some(context.tenant_id.clone()));
    }
    if pat_authenticated {
        if requested_tenant_id.is_some() {
            return Err("an appliance-wide PAT cannot assign tenant ownership");
        }
        return Ok(None);
    }
    if let Some(tenant_id) = requested_tenant_id.as_deref() {
        validate_tenant_id(tenant_id)?;
    }
    Ok(requested_tenant_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A tenant may reference an untenanted resource but only mutate its own.
    #[test]
    fn a_tenant_may_reference_an_operators_resource_but_not_rewrite_it() {
        let tenant = PatTenantContext {
            token_id: "agat_test".into(),
            tenant_id: "tenant-a".into(),
        };
        let other = PatTenantContext {
            token_id: "agat_other".into(),
            tenant_id: "tenant-b".into(),
        };

        // An operator's resource carries no tenant.
        assert!(can_access(None, Some(&tenant)), "referencing it must keep working");
        assert!(!can_mutate(None, Some(&tenant)), "but it is not the tenant's to change");

        // Their own is theirs to do either with.
        assert!(can_access(Some("tenant-a"), Some(&tenant)));
        assert!(can_mutate(Some("tenant-a"), Some(&tenant)));

        // Another tenant's is neither, and was already neither.
        assert!(!can_access(Some("tenant-a"), Some(&other)));
        assert!(!can_mutate(Some("tenant-a"), Some(&other)));

        // An appliance-wide token has no tenant context and is unaffected —
        // the operator must still be able to maintain their own policies.
        assert!(can_mutate(None, None));
        assert!(can_mutate(Some("tenant-a"), None));
    }

    #[test]
    fn validates_and_formats_tenant_resource_target() {
        assert!(validate_tenant_id("acct:eu-west_1.prod").is_ok());
        assert!(validate_tenant_id("").is_err());
        assert!(validate_tenant_id("tenant/escape").is_err());
        assert_eq!(
            canonical_resource_target("123456789012", ResourceKind::Gateways, "gateway-id"),
            "TENANT:123456789012:gateways:gateway-id"
        );
    }

    #[test]
    fn access_and_create_rules_preserve_global_compatibility() {
        let context = PatTenantContext {
            token_id: "agat_test".into(),
            tenant_id: "tenant-a".into(),
        };
        assert!(can_access(Some("tenant-a"), Some(&context)));
        assert!(can_access(None, Some(&context)));
        assert!(!can_access(Some("tenant-b"), Some(&context)));
        assert!(can_access(Some("tenant-b"), None));
        assert!(can_reference(Some("tenant-a"), Some("tenant-a")));
        assert!(can_reference(Some("tenant-a"), None));
        assert!(!can_reference(Some("tenant-a"), Some("tenant-b")));
        assert!(can_reference(None, None));
        assert!(!can_reference(None, Some("tenant-a")));

        assert_eq!(tenant_for_create(None, true, Some(&context)).unwrap(), Some("tenant-a".into()));
        assert!(tenant_for_create(Some("tenant-b".into()), true, Some(&context)).is_err());
        assert!(tenant_for_create(Some("tenant-a".into()), true, None).is_err());
        assert_eq!(tenant_for_create(Some("tenant-a".into()), false, None).unwrap(), Some("tenant-a".into()));
    }

    fn selector(
        header_name: &str,
        broad: bool,
    ) -> TenantSelector {
        TenantSelector {
            header_name: header_name.to_string(),
            broad,
        }
    }

    #[test]
    fn trusted_tenant_header_covers_only_when_asserted_and_case_insensitively_matched() {
        let edge = TrustedTenantHeader {
            header: "X-External-Account".to_string(),
            edge_strips_client_values: true,
        };
        assert!(edge.covers("x-external-account"));
        assert!(edge.covers("X-EXTERNAL-ACCOUNT"));
        assert!(!edge.covers("x-other-header"));

        let unasserted = TrustedTenantHeader {
            header: "x-external-account".to_string(),
            edge_strips_client_values: false,
        };
        assert!(!unasserted.covers("x-external-account"), "presence of the header alone must not be trusted");
    }

    #[test]
    fn header_derived_tenant_permitted_allows_exact_always_and_broad_only_behind_a_covering_trusted_edge() {
        let exact = selector("x-external-account", false);
        let broad = selector("x-external-account", true);
        let covering_edge = TrustedTenantHeader {
            header: "x-external-account".to_string(),
            edge_strips_client_values: true,
        };
        let non_covering_edge = TrustedTenantHeader {
            header: "x-other-header".to_string(),
            edge_strips_client_values: true,
        };
        let unasserted_edge = TrustedTenantHeader {
            header: "x-external-account".to_string(),
            edge_strips_client_values: false,
        };

        // Exact selector: always permitted, trusted edge or not.
        assert!(header_derived_tenant_permitted(&exact, None));
        assert!(header_derived_tenant_permitted(&exact, Some(&covering_edge)));

        // Broad selector: fails closed with no trusted edge, or one that
        // doesn't cover this header, or one whose assertion isn't affirmed.
        assert!(!header_derived_tenant_permitted(&broad, None));
        assert!(!header_derived_tenant_permitted(&broad, Some(&non_covering_edge)));
        assert!(!header_derived_tenant_permitted(&broad, Some(&unasserted_edge)));

        // Broad selector: permitted only behind a covering, asserted trusted edge.
        assert!(header_derived_tenant_permitted(&broad, Some(&covering_edge)));
    }
}
