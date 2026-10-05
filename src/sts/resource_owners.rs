//! Which tenants own an MCP resource on this appliance.
//!
//! The Resource Server accepts a token on issuer, audience and scope alone, so
//! whichever endpoint serves a resource accepts every token minted for it. A
//! tenant-scoped client may therefore mint for a resource only when every
//! endpoint serving it belongs to a tenant the client can reference. Minting
//! checks this, which covers clients created before an endpoint declared the
//! resource and endpoints moved between tenants; saving a client checks it too,
//! as early feedback.
//!
//! Only a declaration the endpoint actually serves counts: its origin must be a
//! public URL of the endpoint's listener and its path the endpoint's own path
//! (`crate::mcp::resource_server::ResourceDeclaration`). A surface or MCP Proxy
//! cannot claim a URI it does not serve, so one tenant cannot block another's
//! clients by declaring its resource. Saving a surface or MCP Proxy refuses a
//! declaration it does not serve, or one another endpoint already serves.

use std::sync::Arc;

use async_trait::async_trait;

use crate::mcp::resource_server::{ResourceDeclaration, proxy_resource_declaration, surface_resource_declarations};
use crate::sts::errors::StsError;

#[async_trait]
pub trait StsResourceOwners: Send + Sync {
    /// The tenant of every endpoint that serves `resource`: `None` for an
    /// appliance-global endpoint. Empty when no endpoint serves it.
    async fn declaring_tenants(
        &self,
        resource: &str,
    ) -> anyhow::Result<Vec<Option<String>>>;
}

/// The endpoint a resource declaration belongs to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResourceEndpoint {
    Surface(String),
    McpProxy(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ResourceClaim {
    resource: String,
    tenant_id: Option<String>,
    endpoint: ResourceEndpoint,
}

/// Why an endpoint's resource declarations cannot be saved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResourceDeclarationError {
    /// The declaration's origin or path is not this endpoint's own.
    NotServed(String),
    /// Another stored endpoint already serves the resource.
    AlreadyServed(String),
    Unavailable,
}

impl std::fmt::Display for ResourceDeclarationError {
    fn fmt(
        &self,
        f: &mut std::fmt::Formatter<'_>,
    ) -> std::fmt::Result {
        match self {
            Self::NotServed(resource) => write!(
                f,
                "mcp_http.authorization.resource '{resource}' must be this endpoint's own public URL: a public URL of \
                 its listener and its own path"
            ),
            Self::AlreadyServed(resource) => {
                write!(f, "mcp_http.authorization.resource '{resource}' is already served by another endpoint")
            }
            Self::Unavailable => write!(f, "MCP resource ownership is unavailable"),
        }
    }
}

/// The resources every stored surface and MCP Proxy serves, whatever its
/// status: a disabled endpoint keeps its resource so it can be re-enabled.
pub struct ApplianceResourceOwners {
    surfaces: Option<Arc<dyn crate::surfaces::AgentSurfaceStore>>,
    proxies: Option<Arc<dyn crate::mcp_proxies::McpProxyStore>>,
    network: Arc<crate::config::NetworkConfig>,
}

impl ApplianceResourceOwners {
    pub fn new(
        surfaces: Option<Arc<dyn crate::surfaces::AgentSurfaceStore>>,
        proxies: Option<Arc<dyn crate::mcp_proxies::McpProxyStore>>,
        network: Arc<crate::config::NetworkConfig>,
    ) -> Self {
        Self { surfaces, proxies, network }
    }

    pub fn network(&self) -> &crate::config::NetworkConfig {
        &self.network
    }

    async fn claims(&self) -> anyhow::Result<Vec<ResourceClaim>> {
        let mut claims = Vec::new();
        if let Some(surfaces) = self.surfaces.as_ref() {
            for surface in surfaces.list_all().await? {
                for declaration in surface_resource_declarations(&surface, &self.network) {
                    if declaration.served {
                        claims.push(ResourceClaim {
                            resource: declaration.resource,
                            tenant_id: surface.tenant_id.clone(),
                            endpoint: ResourceEndpoint::Surface(surface.surface_id.clone()),
                        });
                    }
                }
            }
        }
        if let Some(proxies) = self.proxies.as_ref() {
            for proxy in proxies.list_all().await? {
                if let Some(declaration) = proxy_resource_declaration(&proxy, &self.network)
                    && declaration.served
                {
                    claims.push(ResourceClaim {
                        resource: declaration.resource,
                        tenant_id: proxy.tenant_id.clone(),
                        endpoint: ResourceEndpoint::McpProxy(proxy.id.clone()),
                    });
                }
            }
        }
        Ok(claims)
    }

    /// Refuses declarations `endpoint` does not serve, and resources another
    /// stored endpoint already serves. Two endpoints serving one resource would
    /// both accept every token minted for it.
    pub async fn ensure_endpoint_may_declare(
        &self,
        endpoint: &ResourceEndpoint,
        declarations: &[ResourceDeclaration],
    ) -> Result<(), ResourceDeclarationError> {
        if let Some(declaration) = declarations
            .iter()
            .find(|declaration| !declaration.served)
        {
            return Err(ResourceDeclarationError::NotServed(declaration.resource.clone()));
        }
        if declarations.is_empty() {
            return Ok(());
        }
        let claims = self
            .claims()
            .await
            .map_err(|error| {
                tracing::error!(%error, "Failed to read endpoints while checking MCP resource declarations");
                ResourceDeclarationError::Unavailable
            })?;
        if let Some(declaration) = declarations
            .iter()
            .find(|declaration| {
                claims
                    .iter()
                    .any(|claim| claim.endpoint != *endpoint && claim.resource == declaration.resource)
            })
        {
            return Err(ResourceDeclarationError::AlreadyServed(declaration.resource.clone()));
        }
        Ok(())
    }
}

#[async_trait]
impl StsResourceOwners for ApplianceResourceOwners {
    async fn declaring_tenants(
        &self,
        resource: &str,
    ) -> anyhow::Result<Vec<Option<String>>> {
        Ok(self
            .claims()
            .await?
            .into_iter()
            .filter(|claim| claim.resource == resource)
            .map(|claim| claim.tenant_id)
            .collect())
    }
}

/// No endpoint serves any resource.
#[cfg(test)]
pub struct NoResourceOwners;

#[cfg(test)]
#[async_trait]
impl StsResourceOwners for NoResourceOwners {
    async fn declaring_tenants(
        &self,
        _resource: &str,
    ) -> anyhow::Result<Vec<Option<String>>> {
        Ok(Vec::new())
    }
}

/// Refuses a tenant-scoped client a resource that an endpoint of a tenant it
/// cannot reference serves. The refusal does not say that another tenant holds
/// the resource. Appliance-global clients are administrator-created and keep
/// their reach. Fails closed when the endpoints cannot be read.
pub async fn ensure_client_may_target(
    owners: &dyn StsResourceOwners,
    client_tenant_id: Option<&str>,
    resource: &str,
) -> Result<(), StsError> {
    let Some(client_tenant_id) = client_tenant_id else {
        return Ok(());
    };
    let tenants = owners
        .declaring_tenants(resource)
        .await
        .map_err(|error| {
            tracing::error!(%error, "Failed to read endpoints while checking an MCP resource's owner");
            StsError::ServerError("MCP resource ownership is unavailable".into())
        })?;
    if tenants
        .iter()
        .any(|tenant| !crate::tenancy::can_reference(Some(client_tenant_id), tenant.as_deref()))
    {
        tracing::warn!(
            resource,
            tenant_id = client_tenant_id,
            "Refused an MCP resource token for a resource another tenant serves"
        );
        return Err(StsError::InvalidTarget("MCP resource is not available to this client".into()));
    }
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    struct Fixed(Vec<Option<String>>);

    #[async_trait]
    impl StsResourceOwners for Fixed {
        async fn declaring_tenants(
            &self,
            _resource: &str,
        ) -> anyhow::Result<Vec<Option<String>>> {
            Ok(self.0.clone())
        }
    }

    struct Unreadable;

    #[async_trait]
    impl StsResourceOwners for Unreadable {
        async fn declaring_tenants(
            &self,
            _resource: &str,
        ) -> anyhow::Result<Vec<Option<String>>> {
            anyhow::bail!("store unavailable")
        }
    }

    pub(crate) struct Surfaces(pub(crate) Vec<crate::config::agent_surface::AgentSurface>);

    #[async_trait]
    impl crate::surfaces::AgentSurfaceStore for Surfaces {
        async fn save(
            &self,
            _surface: &crate::config::agent_surface::AgentSurface,
        ) -> anyhow::Result<()> {
            Ok(())
        }

        async fn get(
            &self,
            _surface_id: &str,
        ) -> anyhow::Result<Option<crate::config::agent_surface::AgentSurface>> {
            Ok(None)
        }

        async fn list_all(&self) -> anyhow::Result<Vec<crate::config::agent_surface::AgentSurface>> {
            Ok(self.0.clone())
        }

        async fn delete(
            &self,
            _surface_id: &str,
        ) -> anyhow::Result<()> {
            Ok(())
        }
    }

    fn tenant(id: &str) -> Option<String> {
        Some(id.to_string())
    }

    pub(crate) fn network() -> Arc<crate::config::NetworkConfig> {
        Arc::new(
            serde_json::from_value(serde_json::json!({
                "did": {"domain": "gw.example"},
                "webauthn": {"rp_id": "gw.example", "external_origin": "https://gw.example"},
                "integration": {"types": [], "categories": []},
                "listeners": [{"id": "in", "name": "in", "bind_address": "0.0.0.0", "port": 8443,
                    "protocol": "https", "external_urls": ["https://gw.example"]}],
                "routes": {}
            }))
            .expect("test network must deserialize"),
        )
    }

    pub(crate) fn surface(
        tenant_id: Option<&str>,
        status: &str,
        route: &str,
        resource: &str,
    ) -> crate::config::agent_surface::AgentSurface {
        serde_json::from_value(serde_json::json!({
            "surface_id": format!("surface{}", route.replace('/', "-")),
            "tenant_id": tenant_id,
            "name": format!("surface{route}"),
            "description": "",
            "status": status,
            "tags": [],
            "access_point": {
                "listen_address": "https://gw.example", "route": route, "protocol": "mcp",
                "publish_to_did_document": false, "terminate_trace_id": false
            },
            "target": {
                "endpoint": "https://tools.example.com/mcp", "mcp_tool_policies_enabled": false,
                "identity_injection": {"inject_vp": false}, "mpp_auto_pay": false
            },
            "mcp_http": {"authorization": {"resource": resource, "scopes": []}}
        }))
        .expect("test surface must deserialize")
    }

    fn owners(surfaces: Vec<crate::config::agent_surface::AgentSurface>) -> ApplianceResourceOwners {
        ApplianceResourceOwners::new(Some(Arc::new(Surfaces(surfaces))), None, network())
    }

    #[tokio::test]
    async fn a_tenant_client_may_target_only_resources_every_owner_lets_it_reference() {
        let resource = "https://gw.example/b";
        for (owners, allowed) in [
            // Undeclared: a third-party audience.
            (vec![], true),
            // Its own tenant, or an appliance-global endpoint.
            (vec![tenant("tenant-a")], true),
            (vec![None], true),
            // Another tenant's endpoint serves it.
            (vec![tenant("tenant-b")], false),
            // Served by an endpoint of each tenant: both would accept the token.
            (vec![tenant("tenant-a"), tenant("tenant-b")], false),
        ] {
            let result = ensure_client_may_target(&Fixed(owners.clone()), Some("tenant-a"), resource).await;
            assert_eq!(result.is_ok(), allowed, "{owners:?}: {result:?}");
            if !allowed {
                assert!(matches!(result, Err(StsError::InvalidTarget(_))));
            }
        }
    }

    #[tokio::test]
    async fn appliance_global_clients_keep_their_reach() {
        assert!(
            ensure_client_may_target(&Fixed(vec![tenant("tenant-b")]), None, "https://gw.example/b")
                .await
                .is_ok()
        );
        assert!(
            ensure_client_may_target(&Unreadable, None, "https://gw.example/b")
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn unreadable_endpoints_fail_closed_for_tenant_clients() {
        assert!(matches!(
            ensure_client_may_target(&Unreadable, Some("tenant-a"), "https://gw.example/b").await,
            Err(StsError::ServerError(_))
        ));
    }

    #[tokio::test]
    async fn only_a_resource_an_endpoint_serves_counts_as_owned() {
        let owners = owners(vec![
            surface(Some("tenant-b"), "active", "/b", "https://gw.example/b"),
            // Tenant A declares tenant B's resource on its own surfaces. Neither
            // serves it (wrong path), so neither blocks tenant B.
            surface(Some("tenant-a"), "active", "/squat", "https://gw.example/b"),
            surface(Some("tenant-a"), "disabled", "/parked", "https://gw.example/b"),
            // A disabled surface still owns the resource it serves.
            surface(Some("tenant-c"), "disabled", "/c", "https://gw.example/c"),
            // Wrong origin: the listener has no such public URL.
            surface(Some("tenant-d"), "active", "/d", "https://elsewhere.example/d"),
        ]);
        assert_eq!(
            owners
                .declaring_tenants("https://gw.example/b")
                .await
                .unwrap(),
            vec![tenant("tenant-b")]
        );
        assert_eq!(
            owners
                .declaring_tenants("https://gw.example/c")
                .await
                .unwrap(),
            vec![tenant("tenant-c")]
        );
        assert!(
            owners
                .declaring_tenants("https://elsewhere.example/d")
                .await
                .unwrap()
                .is_empty()
        );
        assert!(
            ensure_client_may_target(&owners, Some("tenant-b"), "https://gw.example/b")
                .await
                .is_ok()
        );
        assert!(matches!(
            ensure_client_may_target(&owners, Some("tenant-a"), "https://gw.example/b").await,
            Err(StsError::InvalidTarget(_))
        ));
    }

    #[tokio::test]
    async fn an_endpoint_may_declare_only_a_resource_it_alone_serves() {
        let owners = owners(vec![surface(Some("tenant-b"), "disabled", "/b", "https://gw.example/b")]);
        let network = network();
        let declarations =
            |surface: &crate::config::agent_surface::AgentSurface| surface_resource_declarations(surface, &network);
        let endpoint = |surface: &crate::config::agent_surface::AgentSurface| {
            ResourceEndpoint::Surface(surface.surface_id.clone())
        };

        let own = surface(Some("tenant-a"), "active", "/a", "https://gw.example/a");
        assert_eq!(
            owners
                .ensure_endpoint_may_declare(&endpoint(&own), &declarations(&own))
                .await,
            Ok(())
        );

        let foreign_path = surface(Some("tenant-a"), "active", "/a", "https://gw.example/b");
        assert_eq!(
            owners
                .ensure_endpoint_may_declare(&endpoint(&foreign_path), &declarations(&foreign_path))
                .await,
            Err(ResourceDeclarationError::NotServed("https://gw.example/b".into()))
        );

        // Same route on a disabled surface escapes the route-collision check,
        // but it would serve the same resource.
        let duplicate = surface(Some("tenant-a"), "disabled", "/b", "https://gw.example/b");
        let duplicate = crate::config::agent_surface::AgentSurface {
            surface_id: "another".into(),
            ..duplicate
        };
        assert_eq!(
            owners
                .ensure_endpoint_may_declare(&endpoint(&duplicate), &declarations(&duplicate))
                .await,
            Err(ResourceDeclarationError::AlreadyServed("https://gw.example/b".into()))
        );

        // Re-saving the surface that already serves it is fine.
        let resaved = surface(Some("tenant-b"), "active", "/b", "https://gw.example/b");
        assert_eq!(
            owners
                .ensure_endpoint_may_declare(&endpoint(&resaved), &declarations(&resaved))
                .await,
            Ok(())
        );
    }
}
