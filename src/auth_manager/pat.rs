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
    EnforceId { kind: ResourceKind, id: String },
    HandlerEnforced,
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
                    | "approve"],
            )
            | (ResourceKind::Gateways, ["trusted-issuers", _])
            | (ResourceKind::ConnectionPoints, ["use" | "exposed-surfaces" | "metrics" | "reconnect"])
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
        assert_eq!(classify_resource_path("/v1/sts/clients/id/future-action"), PathScope::DenyScoped);
        assert_eq!(classify_resource_path("/v1/gateways/id/connection-points/future-action"), PathScope::DenyScoped);
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
