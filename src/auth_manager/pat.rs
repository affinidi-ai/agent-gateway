use std::sync::Arc;

use async_trait::async_trait;
use regex::Regex;

use super::resource_scope::CompiledResourceScope;
use crate::tenancy::ResourceKind;

pub struct PatPrincipal {
    pub user_id: String,
    pub scopes: Option<Vec<String>>,
    pub token_id: String,
    pub delegation_depth: u32,
    pub resource_scope: Option<Arc<CompiledResourceScope>>,
}

#[async_trait]
pub trait PatAuthenticator: Send + Sync {
    async fn authenticate(
        &self,
        token: &str,
    ) -> Option<PatPrincipal>;
}

#[derive(Clone)]
pub struct PatContext(pub Option<Vec<String>>);

#[derive(Clone)]
pub struct PatDelegationContext {
    pub token_id: String,
    pub delegation_depth: u32,
    pub resource_scoped: bool,
}

#[derive(Clone)]
pub struct PatResourceScope(pub Arc<Regex>);

impl PatResourceScope {
    pub fn allows(
        &self,
        id: &str,
    ) -> bool {
        self.0.is_match(id)
    }
}

pub fn scope_allows(
    scope: Option<&PatResourceScope>,
    id: &str,
) -> bool {
    scope.is_none_or(|scope| scope.allows(id))
}

#[derive(Debug, PartialEq, Eq)]
pub enum PathScope {
    EnforceId {
        kind: ResourceKind,
        id: String,
    },
    HandlerEnforced,
    /// The handler enforces the resource for a tenant's token. A write by a
    /// resource-scoped token without a tenant is refused, as for
    /// [`PathScope::Unscoped`]: such a token is no operator, and these routes
    /// would otherwise treat it as one.
    HandlerEnforcedForTenants,
    DenyScoped,
    Unscoped,
}

const HANDLER_ENFORCED_FAMILIES: &[&str] = &["secrets", "api-keys", "certificates"];

fn classify_special_family(
    name: &str,
    rest: &[&str],
) -> Option<PathScope> {
    match (name, rest) {
        ("secrets", [])
        | ("secrets", ["new"])
        | ("secrets", [_])
        | ("secrets", ["tag", _])
        | ("certificates", [])
        | ("certificates", [_])
        | ("api-keys", [])
        | ("api-keys", [_])
        | ("api-keys", [_, _])
        | ("api-keys", [_, _, "revoke" | "rotate"]) => Some(PathScope::HandlerEnforced),
        ("secrets" | "certificates" | "api-keys", _) => Some(PathScope::DenyScoped),
        ("delegation-vault", ["connects"]) | ("delegation-vault", ["connects", _, "complete"]) => {
            Some(PathScope::HandlerEnforced)
        }
        ("delegation-vault", ["grants"]) | ("delegation-vault", ["grants", _]) => {
            Some(PathScope::HandlerEnforcedForTenants)
        }
        ("delegation-vault", _) => Some(PathScope::Unscoped),
        _ => None,
    }
}

fn is_handler_enforced_collection_action(
    kind: ResourceKind,
    rest: &[&str],
) -> bool {
    matches!(
        (kind, rest),
        (ResourceKind::Mediators, ["compatible" | "check-auth"])
            | (ResourceKind::McpProxies, ["validate" | "discover-tools"])
    )
}

fn is_handler_enforced_nested_action(
    kind: ResourceKind,
    tail: &[&str],
) -> bool {
    matches!(
        (kind, tail),
        (ResourceKind::Surfaces, ["variants"])
            | (ResourceKind::Surfaces, ["trust-recorder-status" | "agent-card"])
            | (ResourceKind::Surfaces, ["agent-card", "refresh"])
            | (ResourceKind::Surfaces, ["variants", _])
            | (ResourceKind::Surfaces, ["variants", _, "promote-to-default" | "resolved"])
            | (ResourceKind::SurfaceTemplates, ["export"])
            | (ResourceKind::PolicyDefinitions, ["versions" | "impact" | "simulate"])
            | (
                ResourceKind::Gateways,
                ["integrations"
                    | "policy"
                    | "ping"
                    | "issuer"
                    | "trusted-issuers"
                    | "surfaces"
                    | "exposed-surfaces"
                    | "approve"
                    | "continue"
                    | "mediator-access"],
            )
            | (ResourceKind::Gateways, ["trusted-issuers", _])
            | (
                ResourceKind::ConnectionPoints,
                ["use" | "exposed-surfaces" | "metrics" | "reconnect" | "continue" | "mediator-access"],
            )
            | (ResourceKind::ConnectionPoints, ["messages"])
            | (ResourceKind::ConnectionPoints, ["messages", _])
            | (ResourceKind::ConnectionPoints, ["messages", _, "read"])
            | (ResourceKind::Mediators, ["trust-ping"])
            | (ResourceKind::Issuers, ["register-trust-registry"])
            | (ResourceKind::Integrations, ["trigger"])
            | (ResourceKind::TrustRegistries, ["list-records" | "reconnect"])
    )
}

pub fn classify_resource_path(path: &str) -> PathScope {
    let segments: Vec<&str> = path
        .split('/')
        .filter(|segment| !segment.is_empty())
        .collect();
    let mut family = None;
    for index in 0..segments.len().min(2) {
        if segments[index] == "v1" && index + 1 < segments.len() {
            let candidate = segments[index + 1];
            if HANDLER_ENFORCED_FAMILIES.contains(&candidate)
                || ResourceKind::from_path_family(candidate).is_some()
                || candidate == "sts"
            {
                family = Some((candidate, index + 2));
                break;
            }
        }
    }

    let Some((name, rest_start)) = family else {
        return PathScope::Unscoped;
    };
    if let Some(classification) = classify_special_family(name, &segments[rest_start..]) {
        return classification;
    }

    if name == "sts" {
        if segments.get(rest_start) != Some(&"clients") {
            return PathScope::Unscoped;
        }
        return match &segments[rest_start..] {
            ["clients"] => PathScope::HandlerEnforced,
            ["clients", raw] => PathScope::EnforceId {
                kind: ResourceKind::StsClients,
                id: urlencoding::decode(raw)
                    .map(|value| value.into_owned())
                    .unwrap_or_else(|_| (*raw).into()),
            },
            _ => PathScope::DenyScoped,
        };
    }

    let Some(kind) = ResourceKind::from_path_family(name) else {
        return PathScope::Unscoped;
    };

    let rest = &segments[rest_start..];
    if is_handler_enforced_collection_action(kind, rest) {
        return PathScope::HandlerEnforced;
    }

    if kind == ResourceKind::Gateways && matches!(rest, [_, "connection-points"]) {
        return PathScope::HandlerEnforced;
    }

    match rest {
        [] => PathScope::HandlerEnforced,
        [raw] => PathScope::EnforceId {
            kind,
            id: urlencoding::decode(raw)
                .map(|value| value.into_owned())
                .unwrap_or_else(|_| (*raw).into()),
        },
        [raw, tail @ ..] if is_handler_enforced_nested_action(kind, tail) => PathScope::EnforceId {
            kind,
            id: urlencoding::decode(raw)
                .map(|value| value.into_owned())
                .unwrap_or_else(|_| (*raw).into()),
        },
        _ => PathScope::DenyScoped,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_scoped_and_unscoped_routes() {
        assert_eq!(
            classify_resource_path("/api/v1/policy-definitions/TENANT%3AA%3Apolicy"),
            PathScope::EnforceId {
                kind: ResourceKind::PolicyDefinitions,
                id: "TENANT:A:policy".into(),
            }
        );
        assert_eq!(classify_resource_path("/api/v1/secrets/id"), PathScope::HandlerEnforced);
        assert_eq!(classify_resource_path("/api/v1/secrets/id/future-action"), PathScope::DenyScoped);
        assert_eq!(classify_resource_path("/api/v1/api-keys/surface/key/rotate"), PathScope::HandlerEnforced);
        assert_eq!(classify_resource_path("/api/v1/api-keys/surface/key/future-action"), PathScope::DenyScoped);
        assert_eq!(classify_resource_path("/v1/mcp-proxies/discover-tools"), PathScope::HandlerEnforced);
        assert_eq!(classify_resource_path("/v1/mcp-proxies/discover-tools/future-action"), PathScope::DenyScoped);
        assert_eq!(
            classify_resource_path("/v1/gateways/id"),
            PathScope::EnforceId {
                kind: ResourceKind::Gateways,
                id: "id".into(),
            }
        );
        assert_eq!(
            classify_resource_path("/v1/trust-registries/id/reconnect"),
            PathScope::EnforceId {
                kind: ResourceKind::TrustRegistries,
                id: "id".into(),
            }
        );
        assert_eq!(classify_resource_path("/v1/trust-registries/id/future-action"), PathScope::DenyScoped);
        assert_eq!(
            classify_resource_path("/v1/surfaces/surface%2Fa/trust-recorder-status"),
            PathScope::EnforceId {
                kind: ResourceKind::Surfaces,
                id: "surface/a".into(),
            }
        );
        assert_eq!(classify_resource_path("/v1/surfaces/id/trust-recorder-status/future"), PathScope::DenyScoped);
        for action in ["agent-card", "agent-card/refresh"] {
            assert_eq!(
                classify_resource_path(&format!("/v1/surfaces/surface%2Fa/{action}")),
                PathScope::EnforceId {
                    kind: ResourceKind::Surfaces,
                    id: "surface/a".into(),
                },
                "{action}"
            );
        }
        assert_eq!(classify_resource_path("/v1/surfaces/id/agent-card/future"), PathScope::DenyScoped);
        assert_eq!(classify_resource_path("/v1/surfaces/id/agent-card/refresh/future"), PathScope::DenyScoped);
        assert_eq!(classify_resource_path("/v1/sts/clients/id/future-action"), PathScope::DenyScoped);
        assert_eq!(classify_resource_path("/v1/gateways/id/connection-points/future-action"), PathScope::DenyScoped);
    }

    /// The connect API and the grants by binding are a family a tenant's token
    /// may use, each handler enforcing the surface; the vault's other routes
    /// stay closed to a resource-scoped token for writes, as before. The
    /// removal routes stay closed to a resource-scoped token without a tenant,
    /// which is no operator.
    #[test]
    fn the_connect_and_grant_routes_are_handler_enforced_and_the_rest_of_the_vault_is_unchanged() {
        for path in ["/api/v1/delegation-vault/connects", "/api/v1/delegation-vault/connects/connect-1/complete"] {
            assert_eq!(classify_resource_path(path), PathScope::HandlerEnforced, "{path}");
        }
        for path in [
            "/api/v1/delegation-vault/grants",
            "/api/v1/delegation-vault/grants/grant-1",
            "/v1/delegation-vault/grants",
        ] {
            assert_eq!(classify_resource_path(path), PathScope::HandlerEnforcedForTenants, "{path}");
        }
        for path in [
            "/api/v1/delegation-vault",
            "/api/v1/delegation-vault/token-id",
            "/api/v1/delegation-vault/by-user/hash",
            "/api/v1/delegation-vault/connects/connect-1",
            "/api/v1/delegation-vault/grants/grant-1/other",
        ] {
            assert_eq!(classify_resource_path(path), PathScope::Unscoped, "{path}");
        }
        assert_eq!(ResourceKind::from_path_family("delegation-vault"), Some(ResourceKind::DelegationVault));
    }

    #[test]
    fn gateway_peer_actions_enforce_the_gateway_id() {
        for action in ["ping", "issuer", "trusted-issuers", "trusted-issuers/did%3Aweb%3Apeer.example"] {
            assert_eq!(
                classify_resource_path(&format!("/v1/gateways/id/{action}")),
                PathScope::EnforceId {
                    kind: ResourceKind::Gateways,
                    id: "id".into(),
                },
                "{action}"
            );
        }
        assert_eq!(classify_resource_path("/v1/gateways/id/future-action"), PathScope::DenyScoped);
    }
}
