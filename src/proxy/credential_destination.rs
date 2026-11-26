//! Where a request's Target credential or delegated credential would be sent, decided one way on
//! every leg (the direct path, Fabric send, Fabric receive and Transit Points), and the one way a
//! request is refused for leaving the Target base path. Each leg passes only what is its own: the
//! credentials it would attach, where it sends the request, and the tenant its MCP proxy lookup is
//! scoped to.

use crate::mcp_proxies::handlers::ToolCallDestination;
use crate::mcp_proxies::types::McpProxy;

/// Where a request would send its credential.
pub(crate) enum Destination<'a> {
    /// A URL on an `http(s)` Target, held under the Target base path; the configured agent card
    /// location is allowed too while only the Target credential goes with the request.
    Url { endpoint: &'a str, method: &'a str, url: &'a str, card_location: Option<&'a str> },
    /// The path a `fabric://` peer appends below a base path the gateway does not know.
    AppendedPath(&'a str),
    /// A tool call to an MCP proxy, held to the REST URL its path arguments build.
    ProxyCall { proxy: &'a McpProxy, call: ProxyCall<'a> },
}

/// A request to an MCP proxy, by revision: each is checked by the rule the call it becomes is.
pub(crate) enum ProxyCall<'a> {
    Modern(&'a crate::mcp::request_validation::ValidatedModernMessage),
    Legacy(&'a serde_json::Value),
}

/// Where a request carrying a Target credential (`target_credential`) or a delegated credential
/// (`delegated_credential`) would send it. A request carrying neither is inside the base.
pub(crate) async fn verdict(
    target_credential: bool,
    delegated_credential: bool,
    destination: Destination<'_>,
) -> ToolCallDestination {
    if !target_credential && !delegated_credential {
        return ToolCallDestination::InsideBase;
    }
    let outside = match destination {
        Destination::Url {
            endpoint,
            method,
            url,
            card_location,
        } => !crate::proxy::paths::is_target_credential_destination(
            endpoint,
            method,
            url,
            card_location.filter(|_| !delegated_credential),
        ),
        Destination::AppendedPath(path) => !crate::proxy::paths::appended_path_stays_below_base(path),
        Destination::ProxyCall {
            proxy,
            call: ProxyCall::Modern(request),
        } => return crate::mcp_proxies::handlers::modern_tool_call_destination(proxy, request).await,
        Destination::ProxyCall {
            proxy,
            call: ProxyCall::Legacy(request),
        } => return crate::mcp_proxies::handlers::legacy_tool_call_destination(proxy, request),
    };
    if outside {
        ToolCallDestination::OutsideBase
    } else {
        ToolCallDestination::InsideBase
    }
}

/// Why the MCP proxy a `proxy://` Target names could not be loaded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProxyLookupFailure {
    /// The gateway has no MCP proxy store.
    StoreUnavailable,
    /// The store could not be read.
    LoadFailed,
    /// No proxy has that id, or the surface's tenant may not reference it.
    NotFound,
}

/// The MCP proxy `proxy_id` from `store`, when a surface of `tenant_id` may reference it. Every
/// leg loads the proxy it checks this way, so a proxy it cannot load is refused before any
/// credential is resolved rather than counted as inside the base.
pub(crate) async fn owned_proxy(
    store: Option<&crate::mcp_proxies::FileSystemMcpProxyStore>,
    proxy_id: &str,
    tenant_id: Option<&str>,
) -> Result<McpProxy, ProxyLookupFailure> {
    use crate::mcp_proxies::McpProxyStore;
    store
        .ok_or(ProxyLookupFailure::StoreUnavailable)?
        .get(proxy_id)
        .await
        .map_err(|_| ProxyLookupFailure::LoadFailed)?
        .filter(|proxy| crate::tenancy::can_reference(tenant_id, proxy.tenant_id.as_deref()))
        .ok_or(ProxyLookupFailure::NotFound)
}

/// Logs and records in the VP Audit Log a request refused because it would carry a credential
/// outside the Target base path: a `target_auth_failed` refusal over `target_auth` when the leg
/// sends a Target credential, otherwise a `target_path_refused` refusal at `forward`. Each leg
/// answers in its own shape with `400 target_path_refused`.
pub(crate) fn refuse_outside_base(
    facts: &crate::audit::request_events::RequestFacts<'_>,
    transit_point: Option<&str>,
    target_auth: Option<&crate::config::TargetAuthConfig>,
) {
    tracing::warn!(
        surface = facts.channel_name,
        transit_point,
        via_fabric = facts.via_fabric,
        "Refusing a request outside the Target base path: it would carry a Target or delegated credential"
    );
    crate::proxy::handler::record_credential_destination_refusal(facts, transit_point, target_auth);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn proxy(tenant_id: Option<&str>) -> McpProxy {
        let mut proxy = McpProxy::new(
            "Items".into(),
            String::new(),
            "https://api.example/base".into(),
            serde_json::json!({"openapi": "3.0.0", "info": {"title": "Items", "version": "1.0"}, "paths": {
                "/{id}": {"get": {"operationId": "getItem",
                    "parameters": [{"name": "id", "in": "path", "required": true, "schema": {"type": "string"}}],
                    "responses": {"200": {"description": "OK"}}}}
            }})
            .to_string(),
            "/mcp".into(),
            "/items-destination".into(),
        );
        proxy.tenant_id = tenant_id.map(str::to_string);
        proxy
    }

    #[tokio::test]
    async fn a_request_carrying_no_credential_is_inside_the_base_wherever_it_goes() {
        assert_eq!(
            verdict(false, false, Destination::AppendedPath("/%2e%2e/admin")).await,
            ToolCallDestination::InsideBase
        );
    }

    #[tokio::test]
    async fn the_card_location_takes_only_the_target_credential() {
        let card = || Destination::Url {
            endpoint: "https://api.example/base",
            method: "GET",
            url: "https://api.example/card",
            card_location: Some("/card"),
        };
        assert_eq!(verdict(true, false, card()).await, ToolCallDestination::InsideBase);
        assert_eq!(verdict(true, true, card()).await, ToolCallDestination::OutsideBase);
        assert_eq!(verdict(false, true, card()).await, ToolCallDestination::OutsideBase);
    }

    #[tokio::test]
    async fn a_fabric_path_that_climbs_out_is_outside_the_base() {
        assert_eq!(verdict(false, true, Destination::AppendedPath("/rpc")).await, ToolCallDestination::InsideBase);
        assert_eq!(
            verdict(true, false, Destination::AppendedPath("/%2e%2e/admin")).await,
            ToolCallDestination::OutsideBase
        );
    }

    #[tokio::test]
    async fn a_legacy_tool_call_is_held_to_the_proxys_own_rule() {
        let proxy = proxy(None);
        for (id, expected) in [
            ("1", ToolCallDestination::InsideBase),
            ("/admin", ToolCallDestination::OutsideBase),
            ("//admin", ToolCallDestination::OutsideBase),
        ] {
            let request = serde_json::json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                "params": {"name": "getItem", "arguments": {"id": id}}});
            let destination = Destination::ProxyCall {
                proxy: &proxy,
                call: ProxyCall::Legacy(&request),
            };
            assert_eq!(verdict(false, true, destination).await, expected, "{id}");
        }
    }

    #[tokio::test]
    async fn a_proxy_is_loaded_only_for_a_tenant_that_may_reference_it() {
        use crate::mcp_proxies::McpProxyStore;
        let directory = tempfile::tempdir().unwrap();
        let store = crate::mcp_proxies::FileSystemMcpProxyStore::new(directory.path().to_path_buf())
            .await
            .unwrap();
        let owned = proxy(Some("tenant-a"));
        store
            .create(&owned)
            .await
            .unwrap();
        assert!(
            owned_proxy(Some(&store), &owned.id, Some("tenant-a"))
                .await
                .is_ok()
        );
        assert_eq!(
            owned_proxy(Some(&store), &owned.id, Some("tenant-b"))
                .await
                .err(),
            Some(ProxyLookupFailure::NotFound)
        );
        assert_eq!(
            owned_proxy(Some(&store), "missing", Some("tenant-a"))
                .await
                .err(),
            Some(ProxyLookupFailure::NotFound)
        );
        assert_eq!(
            owned_proxy(None, &owned.id, Some("tenant-a"))
                .await
                .err(),
            Some(ProxyLookupFailure::StoreUnavailable)
        );
    }
}
