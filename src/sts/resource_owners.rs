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
//!
//! Protected resource metadata paths are checked apart from these claims, so
//! they never change who may mint for a resource: a declaring MCP Proxy and a
//! surface's Access Point may not share a path.

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
    /// A declaring MCP Proxy's path holds the Surface Variant separator.
    PathHoldsVariantSeparator(String),
    /// A surface and a declaring MCP Proxy would publish metadata at one path.
    MetadataPathInUse(String),
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
                "MCP resource '{resource}' must be this endpoint's own public URL: a public URL of \
                 its listener and its own path"
            ),
            Self::AlreadyServed(resource) => {
                write!(f, "MCP resource '{resource}' is already served by another endpoint")
            }
            Self::PathHoldsVariantSeparator(path) => write!(
                f,
                "MCP Proxy path '{path}' must not contain '$' or '%24' while it declares \
                 mcp_http.authorization, because '$' separates a Surface Variant alias"
            ),
            Self::MetadataPathInUse(path) => write!(
                f,
                "path '{path}' is already used by another endpoint, so protected resource metadata could not be \
                 published for both"
            ),
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

    /// Refuses a declaring MCP Proxy at a path holding `$` or `%24`, or at the route
    /// or a Surface Variant path of any stored surface, enabled or not. Every
    /// listener serves metadata for every MCP Proxy, so a shared path would leave
    /// the surface's metadata unavailable or let the proxy answer for its variant.
    pub async fn ensure_proxy_metadata_path_free(
        &self,
        proxy: &crate::mcp_proxies::types::McpProxy,
    ) -> Result<(), ResourceDeclarationError> {
        let Some(path) = proxy_metadata_path(proxy) else {
            return Ok(());
        };
        if crate::proxy::paths::route_holds_variant_separator(&path) {
            return Err(ResourceDeclarationError::PathHoldsVariantSeparator(path));
        }
        let Some(surfaces) = self.surfaces.as_ref() else {
            return Ok(());
        };
        let surfaces = surfaces
            .list_all()
            .await
            .map_err(endpoints_unavailable)?;
        if surfaces
            .iter()
            .any(|surface| surface_metadata_paths(surface).any(|used| used == path))
        {
            return Err(ResourceDeclarationError::MetadataPathInUse(path));
        }
        Ok(())
    }

    /// Refuses a surface whose route or Surface Variant path a stored declaring MCP
    /// Proxy, enabled or not, already uses.
    pub async fn ensure_surface_metadata_paths_free(
        &self,
        surface: &crate::config::agent_surface::AgentSurface,
    ) -> Result<(), ResourceDeclarationError> {
        let Some(proxies) = self.proxies.as_ref() else {
            return Ok(());
        };
        let used = proxies
            .list_all()
            .await
            .map_err(endpoints_unavailable)?
            .iter()
            .filter_map(proxy_metadata_path)
            .collect::<std::collections::HashSet<_>>();
        match surface_metadata_paths(surface).find(|path| used.contains(path)) {
            Some(path) => Err(ResourceDeclarationError::MetadataPathInUse(path)),
            None => Ok(()),
        }
    }
}

fn endpoints_unavailable(error: anyhow::Error) -> ResourceDeclarationError {
    tracing::error!(%error, "Failed to read endpoints while checking protected resource metadata paths");
    ResourceDeclarationError::Unavailable
}

/// The path an MCP Proxy publishes protected resource metadata at, when it declares
/// `mcp_http.authorization`.
fn proxy_metadata_path(proxy: &crate::mcp_proxies::types::McpProxy) -> Option<String> {
    proxy
        .mcp_http
        .as_ref()?
        .authorization
        .as_ref()
        .map(|_| proxy.full_path())
}

/// The paths a surface's Access Point may publish protected resource metadata at: its
/// route and `<route>$alias` for every Surface Variant, enabled or not.
fn surface_metadata_paths(surface: &crate::config::agent_surface::AgentSurface) -> impl Iterator<Item = String> + '_ {
    use crate::protocols::protected_resource::access_point_path;
    std::iter::once(None)
        .chain(
            surface
                .variants
                .iter()
                .map(|variant| Some(variant.alias.as_str())),
        )
        .filter_map(|alias| access_point_path(surface, alias))
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

    pub(crate) struct Proxies(pub(crate) Vec<crate::mcp_proxies::types::McpProxy>);

    #[async_trait]
    impl crate::mcp_proxies::McpProxyStore for Proxies {
        async fn create(
            &self,
            _proxy: &crate::mcp_proxies::types::McpProxy,
        ) -> anyhow::Result<()> {
            Ok(())
        }

        async fn get(
            &self,
            _id: &str,
        ) -> anyhow::Result<Option<crate::mcp_proxies::types::McpProxy>> {
            Ok(None)
        }

        async fn list_all(&self) -> anyhow::Result<Vec<crate::mcp_proxies::types::McpProxy>> {
            Ok(self.0.clone())
        }

        async fn delete(
            &self,
            _id: &str,
        ) -> anyhow::Result<()> {
            Ok(())
        }

        async fn update(
            &self,
            _proxy: &crate::mcp_proxies::types::McpProxy,
        ) -> anyhow::Result<()> {
            Ok(())
        }
    }

    struct UnreadableStores;

    #[async_trait]
    impl crate::surfaces::AgentSurfaceStore for UnreadableStores {
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
            anyhow::bail!("store unavailable")
        }

        async fn delete(
            &self,
            _surface_id: &str,
        ) -> anyhow::Result<()> {
            Ok(())
        }
    }

    #[async_trait]
    impl crate::mcp_proxies::McpProxyStore for UnreadableStores {
        async fn create(
            &self,
            _proxy: &crate::mcp_proxies::types::McpProxy,
        ) -> anyhow::Result<()> {
            Ok(())
        }

        async fn get(
            &self,
            _id: &str,
        ) -> anyhow::Result<Option<crate::mcp_proxies::types::McpProxy>> {
            Ok(None)
        }

        async fn list_all(&self) -> anyhow::Result<Vec<crate::mcp_proxies::types::McpProxy>> {
            anyhow::bail!("store unavailable")
        }

        async fn delete(
            &self,
            _id: &str,
        ) -> anyhow::Result<()> {
            Ok(())
        }

        async fn update(
            &self,
            _proxy: &crate::mcp_proxies::types::McpProxy,
        ) -> anyhow::Result<()> {
            Ok(())
        }
    }

    pub(crate) fn declaring_proxy(path: &str) -> crate::mcp_proxies::types::McpProxy {
        let mut proxy = plain_proxy(path);
        proxy.mcp_http = Some(
            serde_json::from_value(serde_json::json!({
                "authorization": {"resource": format!("https://gw.example{path}"), "scopes": []}
            }))
            .expect("test mcp_http must deserialize"),
        );
        proxy
    }

    fn plain_proxy(path: &str) -> crate::mcp_proxies::types::McpProxy {
        crate::mcp_proxies::types::McpProxy::new(
            "proxy".into(),
            String::new(),
            "https://api.example".into(),
            String::new(),
            String::new(),
            path.into(),
        )
    }

    pub(crate) fn with_variants(
        mut surface: crate::config::agent_surface::AgentSurface
    ) -> crate::config::agent_surface::AgentSurface {
        surface.variants = serde_json::from_value(serde_json::json!([
            { "id": "v-dev", "alias": "dev", "name": "dev", "enabled": true, "overrides": {} },
            { "id": "v-off", "alias": "off", "name": "off", "enabled": false, "overrides": {} }
        ]))
        .expect("test variants must deserialize");
        surface
    }

    fn metadata_owners(
        surfaces: Vec<crate::config::agent_surface::AgentSurface>,
        proxies: Vec<crate::mcp_proxies::types::McpProxy>,
    ) -> ApplianceResourceOwners {
        ApplianceResourceOwners::new(Some(Arc::new(Surfaces(surfaces))), Some(Arc::new(Proxies(proxies))), network())
    }

    #[tokio::test]
    async fn a_declaring_proxy_cannot_publish_metadata_at_a_surface_path() {
        let owners = metadata_owners(
            vec![with_variants(surface(Some("tenant-a"), "disabled", "/smoke", "https://gw.example/smoke"))],
            vec![],
        );
        for (proxy, expected) in [
            (declaring_proxy("/smoke"), Err(ResourceDeclarationError::MetadataPathInUse("/smoke".into()))),
            (
                declaring_proxy("/smoke$dev"),
                Err(ResourceDeclarationError::PathHoldsVariantSeparator("/smoke$dev".into())),
            ),
            (
                declaring_proxy("/smoke%24off"),
                Err(ResourceDeclarationError::PathHoldsVariantSeparator("/smoke%24off".into())),
            ),
            (declaring_proxy("/other"), Ok(())),
            (plain_proxy("/smoke"), Ok(())),
            (plain_proxy("/smoke$dev"), Ok(())),
        ] {
            let path = proxy.full_path();
            assert_eq!(
                owners
                    .ensure_proxy_metadata_path_free(&proxy)
                    .await,
                expected,
                "{path}"
            );
        }
    }

    #[tokio::test]
    async fn a_surface_cannot_take_a_path_a_declaring_proxy_publishes_metadata_at() {
        let owners = metadata_owners(
            vec![],
            vec![declaring_proxy("/smoke"), declaring_proxy("/base$off"), plain_proxy("/plain")],
        );
        let route = |route: &str| surface(Some("tenant-a"), "active", route, &format!("https://gw.example{route}"));
        for (surface, expected) in [
            (route("/smoke"), Err(ResourceDeclarationError::MetadataPathInUse("/smoke".into()))),
            (with_variants(route("/base")), Err(ResourceDeclarationError::MetadataPathInUse("/base$off".into()))),
            (route("/base"), Ok(())),
            (route("/plain"), Ok(())),
        ] {
            let path = surface
                .access_point
                .route
                .clone();
            assert_eq!(
                owners
                    .ensure_surface_metadata_paths_free(&surface)
                    .await,
                expected,
                "{path}"
            );
        }
    }

    #[tokio::test]
    async fn unreadable_stores_fail_metadata_path_checks_closed() {
        let owners =
            ApplianceResourceOwners::new(Some(Arc::new(UnreadableStores)), Some(Arc::new(UnreadableStores)), network());
        assert_eq!(
            owners
                .ensure_proxy_metadata_path_free(&declaring_proxy("/smoke"))
                .await,
            Err(ResourceDeclarationError::Unavailable)
        );
        assert_eq!(
            owners
                .ensure_surface_metadata_paths_free(&surface(None, "active", "/smoke", "https://gw.example/smoke"))
                .await,
            Err(ResourceDeclarationError::Unavailable)
        );
        assert_eq!(
            owners
                .ensure_proxy_metadata_path_free(&plain_proxy("/smoke"))
                .await,
            Ok(()),
            "a proxy that declares nothing publishes no metadata"
        );
    }
}
