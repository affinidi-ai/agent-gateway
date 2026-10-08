use axum::http::HeaderMap;
use axum::{Extension, Json, extract::Path, http::StatusCode};
use bytes::Bytes;
use reqwest::header::{HeaderMap as ReqwestHeaderMap, HeaderName, HeaderValue};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

use super::McpProxyStore;
use super::types::{CreateMcpProxyRequest, McpProxy, McpProxyWriteResponse, UpdateMcpProxyRequest};
use crate::auth_manager::pat::{PatContext, PatResourceScope};
use crate::mcp::sse_server::SseSessionManager;
use crate::tenancy::{
    PatTenantContext, ResourceKind, can_access, can_mutate, scope_allows_resource, tenant_for_create,
};
use crate::{channel_info, channel_warn};

fn tenant_context(context: &Option<Extension<PatTenantContext>>) -> Option<&PatTenantContext> {
    context
        .as_ref()
        .map(|Extension(context)| context)
}

fn resource_scope(scope: &Option<Extension<PatResourceScope>>) -> Option<&PatResourceScope> {
    scope
        .as_ref()
        .map(|Extension(scope)| scope)
}

fn mcp_proxy_allowed(
    proxy: &McpProxy,
    context: Option<&PatTenantContext>,
    scope: Option<&PatResourceScope>,
) -> bool {
    can_access(proxy.tenant_id.as_deref(), context)
        && scope_allows_resource(scope, context, ResourceKind::McpProxies, &proxy.id)
}

/// A caller-chosen proxy id. It names the record's file on disk and is embedded
/// in `TENANT:{tenant}:mcp-proxies:{id}` scope targets, so path separators, dots
/// and colons are all excluded.
fn is_valid_mcp_proxy_id(id: &str) -> bool {
    let bytes = id.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 128
        && bytes[0].is_ascii_alphanumeric()
        && bytes
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || *b == b'-' || *b == b'_')
}

/// Trim a `managed_by` label, treating blank as none. Bounded and printable
/// because the dashboard renders it.
fn normalise_managed_by(raw: Option<String>) -> Result<Option<String>, (StatusCode, String)> {
    let Some(label) = raw
        .as_deref()
        .map(str::trim)
        .filter(|l| !l.is_empty())
    else {
        return Ok(None);
    };
    if label.chars().count() > 64
        || label
            .chars()
            .any(char::is_control)
    {
        return Err((StatusCode::BAD_REQUEST, "managed_by must be at most 64 printable characters".to_string()));
    }
    Ok(Some(label.to_string()))
}

/// May this caller change or delete the proxy? Reading an operator's proxy is
/// allowed so a tenant surface can front it; rewriting it is not.
fn mcp_proxy_writable(
    proxy: &McpProxy,
    context: Option<&PatTenantContext>,
    scope: Option<&PatResourceScope>,
) -> bool {
    can_mutate(proxy.tenant_id.as_deref(), context)
        && scope_allows_resource(scope, context, ResourceKind::McpProxies, &proxy.id)
}

fn discovery_secret_allowed(
    tenant_id: Option<&str>,
    secret_id: &str,
    context: Option<&PatTenantContext>,
    scope: Option<&PatResourceScope>,
) -> bool {
    can_access(tenant_id, context) && scope_allows_resource(scope, context, ResourceKind::Secrets, secret_id)
}

// Import rmcp-openapi for MCP Server functionality
use rmcp_openapi::Server as McpServer;
use url::Url;

/// Flatten `request_body` out of an MCP tool's inputSchema.
///
/// rmcp-openapi wraps POST request body properties under a `request_body` key.
/// This lifts those properties to the top level so MCP clients see a flat schema.
/// Other parameters (query, path, header) are left untouched.
fn flatten_input_schema(schema: &serde_json::Value) -> serde_json::Value {
    let Some(obj) = schema.as_object() else {
        return schema.clone();
    };

    let Some(properties) = obj
        .get("properties")
        .and_then(|p| p.as_object())
    else {
        return schema.clone();
    };

    // Check if there's a request_body property
    let Some(rb_schema) = properties.get("request_body") else {
        return schema.clone();
    };

    // Get the request_body's own properties
    let Some(rb_props) = rb_schema
        .get("properties")
        .and_then(|p| p.as_object())
    else {
        return schema.clone();
    };

    // Build new properties: everything except request_body, plus request_body's children
    let mut new_properties = serde_json::Map::new();
    for (key, val) in properties {
        if key != "request_body" {
            new_properties.insert(key.clone(), val.clone());
        }
    }
    for (key, val) in rb_props {
        new_properties.insert(key.clone(), val.clone());
    }

    // Build new required: merge top-level (minus request_body) with request_body's required
    let mut new_required: Vec<serde_json::Value> = obj
        .get("required")
        .and_then(|r| r.as_array())
        .map(|arr| {
            arr.iter()
                .filter(|v| v.as_str() != Some("request_body"))
                .cloned()
                .collect()
        })
        .unwrap_or_default();

    if let Some(rb_required) = rb_schema
        .get("required")
        .and_then(|r| r.as_array())
    {
        for req in rb_required {
            if !new_required.contains(req) {
                new_required.push(req.clone());
            }
        }
    }

    let mut new_schema = obj.clone();
    new_schema.insert("properties".to_string(), serde_json::Value::Object(new_properties));
    if !new_required.is_empty() {
        new_schema.insert("required".to_string(), serde_json::Value::Array(new_required));
    } else {
        new_schema.remove("required");
    }

    serde_json::Value::Object(new_schema)
}

fn modern_input_schema(
    schema: &serde_json::Value,
    flatten: bool,
) -> Result<serde_json::Value, String> {
    crate::mcp::tool_headers::ToolHeaderBindings::compile(schema)?;
    if !flatten {
        return Ok(schema.clone());
    }
    let Some(properties) = schema
        .get("properties")
        .and_then(serde_json::Value::as_object)
    else {
        return Ok(schema.clone());
    };
    let Some(body) = properties.get("request_body") else {
        return Ok(schema.clone());
    };
    let body = body
        .as_object()
        .ok_or("Cannot flatten a non-object request body schema")?;
    let body_properties = body
        .get("properties")
        .and_then(serde_json::Value::as_object)
        .ok_or("Cannot flatten a request body without static properties")?;
    if body
        .get("type")
        .and_then(serde_json::Value::as_str)
        != Some("object")
        || body.keys().any(|key| {
            !matches!(
                key.as_str(),
                "type" | "properties" | "required" | "title" | "description" | "additionalProperties"
            )
        })
    {
        return Err("Cannot flatten a request body with non-property constraints or annotations".to_string());
    }
    if body_properties
        .keys()
        .any(|key| properties.contains_key(key) || key == "timeout_seconds")
    {
        return Err("Cannot flatten colliding request body and tool parameter names".to_string());
    }
    let required_body = schema
        .get("required")
        .and_then(serde_json::Value::as_array)
        .is_some_and(|required| {
            required
                .iter()
                .any(|name| name.as_str() == Some("request_body"))
        });
    if !required_body
        && body
            .get("required")
            .and_then(serde_json::Value::as_array)
            .is_some_and(|required| !required.is_empty())
    {
        return Err("Cannot flatten required properties of an optional request body".to_string());
    }
    let mut flattened = flatten_input_schema(schema);
    flattened["additionalProperties"] = body
        .get("additionalProperties")
        .cloned()
        .unwrap_or(serde_json::Value::Bool(true));
    crate::mcp::tool_headers::ToolHeaderBindings::compile(&flattened)?;
    Ok(flattened)
}

fn modern_tool_input_schema(
    server: &McpServer,
    metadata: &rmcp_openapi::ToolMetadata,
    flatten: bool,
) -> Result<serde_json::Value, String> {
    let mut schema = metadata.parameters.clone();
    let content_type =
        super::modern_rest::request_content_type(&server.openapi_spec, metadata).map_err(|error| error.to_string())?;
    let path = server
        .openapi_spec
        .get("paths")
        .and_then(|paths| paths.get(&metadata.path))
        .map(|path| super::modern_rest::local_reference(&server.openapi_spec, path))
        .transpose()
        .map_err(|error| error.to_string())?;
    let operation = path.and_then(|path| {
        path.get(
            metadata
                .method
                .to_ascii_lowercase(),
        )
    });
    if let Some(properties) = schema
        .get_mut("properties")
        .and_then(serde_json::Value::as_object_mut)
    {
        for parameter in [path, operation]
            .into_iter()
            .flatten()
            .filter_map(|container| {
                container
                    .get("parameters")
                    .and_then(serde_json::Value::as_array)
            })
            .flatten()
        {
            let parameter = super::modern_rest::local_reference(&server.openapi_spec, parameter)
                .map_err(|error| error.to_string())?;
            let Some(source_schema) = parameter.get("schema") else { continue };
            let name = parameter
                .get("name")
                .and_then(serde_json::Value::as_str);
            let location = parameter
                .get("in")
                .and_then(serde_json::Value::as_str);
            if let Some((key, _)) = metadata
                .parameter_mappings
                .iter()
                .find(|(_, mapping)| {
                    Some(mapping.original_name.as_str()) == name && Some(mapping.location.as_str()) == location
                })
                && properties.contains_key(key)
            {
                properties.insert(key.clone(), source_schema.clone());
            }
        }
    }
    let request_schema = operation
        .and_then(|operation| operation.get("requestBody"))
        .map(|body| super::modern_rest::local_reference(&server.openapi_spec, body))
        .transpose()
        .map_err(|error| error.to_string())?
        .and_then(|body| body.get("content"))
        .and_then(|content| content.get(&content_type))
        .and_then(|content| content.get("schema"));
    if let Some(request_schema) = request_schema
        && content_type != "multipart/form-data"
        && let Some(properties) = schema
            .get_mut("properties")
            .and_then(serde_json::Value::as_object_mut)
        && properties.contains_key("request_body")
    {
        properties.insert("request_body".to_string(), request_schema.clone());
    }
    let mut schema = modern_input_schema(&schema, flatten)?;
    super::modern_rest::retain_component_schemas(&mut schema, &server.openapi_spec)
        .map_err(|error| error.to_string())?;
    super::modern_rest::compile_schema(&schema).map_err(|error| error.to_string())?;
    Ok(schema)
}

/// If a tool expects `request_body` but the caller sent flat arguments,
/// wrap them into `{"request_body": {...}}` so rmcp-openapi can route them
/// to the HTTP POST body correctly.
fn wrap_request_body_if_needed(
    server: &McpServer,
    tool_name: &str,
    arguments: serde_json::Value,
) -> serde_json::Value {
    // Already has request_body — pass through
    if arguments
        .get("request_body")
        .is_some()
    {
        return arguments;
    }

    // Check if this tool has a request_body parameter mapping
    let has_request_body = server
        .get_tool_metadata(tool_name)
        .map(|m| {
            m.parameters
                .get("properties")
                .and_then(|p| p.get("request_body"))
                .is_some()
        })
        .unwrap_or(false);

    if !has_request_body {
        return arguments;
    }

    // Separate known non-body params from body params
    let metadata = match server.get_tool_metadata(tool_name) {
        Some(m) => m,
        None => return arguments,
    };

    let args_obj = match arguments.as_object() {
        Some(o) => o,
        None => return arguments,
    };

    // Collect parameter names that are NOT request_body (query, path, header, cookie params)
    let non_body_params: Vec<String> = metadata
        .parameter_mappings
        .iter()
        .filter(|(k, m)| *k != "request_body" && m.location != "body")
        .map(|(k, _)| k.clone())
        .collect();

    let mut wrapper = serde_json::Map::new();
    let mut body = serde_json::Map::new();

    for (key, val) in args_obj {
        if key == "timeout_seconds" || non_body_params.contains(key) {
            wrapper.insert(key.clone(), val.clone());
        } else {
            body.insert(key.clone(), val.clone());
        }
    }

    if !body.is_empty() {
        wrapper.insert("request_body".to_string(), serde_json::Value::Object(body));
    }

    serde_json::Value::Object(wrapper)
}

/// Global MCP Server manager - keeps track of running MCP servers
pub struct McpServerManager {
    servers: RwLock<HashMap<String, RegisteredCatalogs>>,
}

impl Default for McpServerManager {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone)]
struct RegisteredCatalogs {
    legacy: Option<Arc<RwLock<McpServer>>>,
    modern: Arc<RwLock<McpServer>>,
    warning: Option<String>,
}

impl McpServerManager {
    pub fn new() -> Self {
        Self {
            servers: RwLock::new(HashMap::new()),
        }
    }

    /// Create and register a new MCP Server for the given proxy. Returns a
    /// warning when only the modern catalog could be registered.
    pub async fn create_server(
        &self,
        proxy: &McpProxy,
    ) -> Result<Option<String>, String> {
        // Parse the OpenAPI spec from YAML to JSON
        let openapi_json: serde_json::Value =
            serde_yaml::from_str(&proxy.openapi_spec).map_err(|e| format!("Failed to parse OpenAPI spec: {}", e))?;

        // Parse the base URL
        let base_url = Url::parse(&proxy.base_url).map_err(|e| format!("Invalid base URL: {}", e))?;

        // Build and load the MCP server
        let mut server = McpServer::builder()
            .openapi_spec(openapi_json)
            .base_url(base_url)
            .build();

        let catalogs = match server.load_openapi_spec() {
            Ok(()) => {
                let server = Arc::new(RwLock::new(server));
                RegisteredCatalogs {
                    legacy: Some(server.clone()),
                    modern: server,
                    warning: None,
                }
            }
            Err(error) => {
                let original = server.openapi_spec.clone();
                server.openapi_spec = super::modern_rest::routing_spec(&original).map_err(|error| error.to_string())?;
                server
                    .load_openapi_spec()
                    .map_err(|error| format!("Failed to load modern tool routing: {error}"))?;
                server.openapi_spec = original;
                warn!(proxy_id = %proxy.id, error = %error, "OpenAPI schema is unavailable to the legacy tool catalog");
                RegisteredCatalogs {
                    legacy: None,
                    modern: Arc::new(RwLock::new(server)),
                    warning: Some(format!(
                        "OpenAPI spec is unavailable to the MCP {legacy} tool catalog, so {legacy} clients cannot use this proxy: {error}",
                        legacy = crate::mcp::MCP_LEGACY_VERSION
                    )),
                }
            }
        };
        let warning = catalogs.warning.clone();
        self.servers
            .write()
            .await
            .insert(proxy.id.clone(), catalogs);

        info!("✓ Created MCP Server for proxy '{}' at endpoint '{}'", proxy.name, proxy.endpoint_path);
        Ok(warning)
    }

    /// Remove an MCP Server
    pub async fn remove_server(
        &self,
        proxy_id: &str,
    ) {
        let mut servers = self.servers.write().await;
        servers.remove(proxy_id);
        info!("Removed MCP Server for proxy ID: {}", proxy_id);
    }

    /// Get an MCP Server by proxy ID
    #[allow(dead_code)]
    pub async fn get_server(
        &self,
        proxy_id: &str,
    ) -> Option<Arc<RwLock<McpServer>>> {
        let servers = self.servers.read().await;
        servers
            .get(proxy_id)
            .and_then(|catalogs| catalogs.legacy.clone())
    }

    async fn get_catalogs(
        &self,
        proxy_id: &str,
    ) -> Option<RegisteredCatalogs> {
        self.servers
            .read()
            .await
            .get(proxy_id)
            .cloned()
    }

    /// The converter warning of the catalogs currently registered for a proxy.
    async fn catalog_warning(
        &self,
        proxy_id: &str,
    ) -> Option<String> {
        self.get_catalogs(proxy_id)
            .await
            .and_then(|catalogs| catalogs.warning)
    }

    /// Reload a server (useful when proxy config changes)
    pub async fn reload_server(
        &self,
        proxy: &McpProxy,
    ) -> Result<Option<String>, String> {
        self.create_server(proxy)
            .await
    }
}

/// List all MCP Proxies
pub async fn list_mcp_proxies<S: McpProxyStore>(
    Extension(store): Extension<Arc<S>>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
) -> Result<Json<Vec<McpProxy>>, (StatusCode, String)> {
    let mut proxies = store
        .list_all()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let context = tenant_context(&context);
    let scope = resource_scope(&scope);
    proxies.retain(|proxy| mcp_proxy_allowed(proxy, context, scope));
    Ok(Json(proxies))
}

/// Get a specific MCP Proxy by ID
pub async fn get_mcp_proxy<S: McpProxyStore>(
    Extension(store): Extension<Arc<S>>,
    Path(id): Path<String>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
) -> Result<Json<McpProxy>, (StatusCode, String)> {
    let proxy = store
        .get(&id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or_else(|| (StatusCode::NOT_FOUND, "MCP Proxy not found".to_string()))?;
    if !mcp_proxy_allowed(&proxy, tenant_context(&context), resource_scope(&scope)) {
        return Err((StatusCode::NOT_FOUND, "MCP Proxy not found".to_string()));
    }
    Ok(Json(proxy))
}

#[derive(Debug, Deserialize)]
pub struct DiscoverMcpToolsRequest {
    pub target_endpoint: Option<String>,
    pub mcp_proxy_id: Option<String>,
    pub target_auth: Option<DiscoverTargetAuthConfig>,
}

#[derive(Debug, Deserialize)]
pub struct DiscoverTargetAuthConfig {
    pub enabled: bool,
    pub method: Option<String>,
    pub secret_id: Option<String>,
    pub header_name: Option<String>,
    pub header_format: Option<String>,
    pub fallback: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct DiscoverMcpTool {
    pub name: String,
}

#[derive(Debug, Serialize)]
pub struct DiscoverMcpToolsResponse {
    pub tools: Vec<DiscoverMcpTool>,
}

pub async fn discover_mcp_tools<S: McpProxyStore>(
    Extension(store): Extension<Arc<S>>,
    Extension(manager): Extension<Arc<McpServerManager>>,
    Extension(secrets_store): Extension<Option<Arc<dyn crate::secrets::SecretsStore>>>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
    Json(request): Json<DiscoverMcpToolsRequest>,
) -> Result<Json<DiscoverMcpToolsResponse>, (StatusCode, String)> {
    let tools = if let Some(proxy_id) = resolve_proxy_id(&request) {
        discover_proxy_tools(&store, &manager, &proxy_id, tenant_context(&context), resource_scope(&scope)).await?
    } else {
        if scope.is_some() {
            return Err((
                StatusCode::FORBIDDEN,
                "Resource-scoped access tokens must discover tools through an authorized MCP Proxy".to_string(),
            ));
        }
        let target_endpoint = request
            .target_endpoint
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                (StatusCode::BAD_REQUEST, "Either mcp_proxy_id or target_endpoint is required".to_string())
            })?;

        if target_endpoint.starts_with("fabric://") {
            return Err((
                StatusCode::BAD_REQUEST,
                "Tool discovery is not supported for fabric:// MCP targets".to_string(),
            ));
        }
        let target_endpoint = crate::url_validation::validate_resolved_url(target_endpoint)
            .map_err(|error| (StatusCode::BAD_REQUEST, format!("Invalid MCP target endpoint: {error}")))?;

        let pinned_client = pin_discovery_client(target_endpoint.as_str()).await?;

        discover_remote_tools(
            &pinned_client,
            target_endpoint.as_str(),
            request.target_auth.as_ref(),
            &secrets_store,
            tenant_context(&context),
            resource_scope(&scope),
        )
        .await?
    };

    Ok(Json(DiscoverMcpToolsResponse { tools }))
}

/// Build a per-request Strict-pinned, redirect-disabled client for MCP tool
/// discovery against a caller-supplied `target_endpoint`.
///
/// Resolves DNS once and pins the connection to the vetted address so the host
/// cannot rebind to an internal/metadata IP between validation and connect
/// (SSRF rebinding TOCTOU). The resolved IP stays log-only; the caller-facing
/// error keeps the generic "Invalid MCP target endpoint" message.
async fn pin_discovery_client(target_endpoint: &str) -> Result<reqwest::Client, (StatusCode, String)> {
    let raw = target_endpoint.to_string();
    let pinned = tokio::task::spawn_blocking(move || {
        crate::egress::pinned_strict_client(
            &raw,
            std::time::Duration::from_secs(crate::http_client::EXTERNAL_TIMEOUT_SECS),
        )
    })
    .await
    .map_err(|error| {
        error!(%error, "MCP discovery pin task failed");
        (StatusCode::INTERNAL_SERVER_ERROR, "Failed to resolve MCP target endpoint".to_string())
    })?;

    match pinned {
        Ok((client, target)) => {
            debug!(addrs = ?target.addrs, "Pinned MCP discovery client to vetted address");
            Ok(client)
        }
        Err(error) => {
            warn!(%error, "MCP discovery target endpoint blocked by egress policy");
            Err((StatusCode::BAD_REQUEST, "Invalid MCP target endpoint".to_string()))
        }
    }
}

fn resolve_proxy_id(request: &DiscoverMcpToolsRequest) -> Option<String> {
    request
        .mcp_proxy_id
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .or_else(|| {
            request
                .target_endpoint
                .as_deref()
                .and_then(|target| target.strip_prefix("proxy://"))
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(ToOwned::to_owned)
        })
}

async fn discover_proxy_tools<S: McpProxyStore>(
    store: &Arc<S>,
    manager: &Arc<McpServerManager>,
    proxy_id: &str,
    context: Option<&PatTenantContext>,
    scope: Option<&PatResourceScope>,
) -> Result<Vec<DiscoverMcpTool>, (StatusCode, String)> {
    let proxy = store
        .get(proxy_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or_else(|| (StatusCode::NOT_FOUND, "MCP Proxy not found".to_string()))?;
    if !mcp_proxy_allowed(&proxy, context, scope) {
        return Err((StatusCode::NOT_FOUND, "MCP Proxy not found".to_string()));
    }

    if manager
        .get_catalogs(proxy_id)
        .await
        .is_none()
    {
        manager
            .create_server(&proxy)
            .await
            .map_err(|e| (StatusCode::BAD_REQUEST, format!("Failed to initialize MCP proxy: {}", e)))?;
    }

    let catalogs = manager
        .get_catalogs(proxy_id)
        .await
        .ok_or_else(|| (StatusCode::INTERNAL_SERVER_ERROR, "MCP proxy server is not available".to_string()))?;

    let server = catalogs.modern.read().await;
    let mut tools = server
        .get_tool_names()
        .into_iter()
        .filter_map(|tool_name| {
            server
                .get_tool_metadata(&tool_name)
                .map(|metadata| DiscoverMcpTool { name: metadata.name.clone() })
        })
        .collect::<Vec<_>>();

    tools.sort_by(|left, right| left.name.cmp(&right.name));
    Ok(tools)
}

async fn discover_remote_tools(
    client: &reqwest::Client,
    target_endpoint: &str,
    target_auth: Option<&DiscoverTargetAuthConfig>,
    secrets_store: &Option<Arc<dyn crate::secrets::SecretsStore>>,
    context: Option<&PatTenantContext>,
    scope: Option<&PatResourceScope>,
) -> Result<Vec<DiscoverMcpTool>, (StatusCode, String)> {
    let channel_name = "mcp-tool-discovery";
    let extra_headers = build_discovery_headers(target_auth, secrets_store, context, scope, channel_name).await?;

    let initialize_request = serde_json::json!({
        "jsonrpc": "2.0",
        "id": "init",
        "method": "initialize",
        "params": {
            "protocolVersion": crate::mcp::MCP_PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": {
                "name": "agent-gateway",
                "version": env!("CARGO_PKG_VERSION")
            }
        }
    });
    let initialize_response =
        send_discovery_request(client, target_endpoint, initialize_request, channel_name, extra_headers.as_ref())
            .await?;
    ensure_jsonrpc_success(&initialize_response)?;

    let initialized_notification = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "notifications/initialized"
    });
    let _ =
        send_discovery_request(client, target_endpoint, initialized_notification, channel_name, extra_headers.as_ref())
            .await;

    let tool_list_response = send_discovery_request(
        client,
        target_endpoint,
        serde_json::json!({
            "jsonrpc": "2.0",
            "id": "tools-list",
            "method": "tools/list",
            "params": {}
        }),
        channel_name,
        extra_headers.as_ref(),
    )
    .await?;
    let response_json = ensure_jsonrpc_success(&tool_list_response)?;

    let mut tools = response_json
        .get("result")
        .and_then(|result| result.get("tools"))
        .and_then(|tools| tools.as_array())
        .ok_or_else(|| (StatusCode::BAD_GATEWAY, "MCP server returned an invalid tools/list response".to_string()))?
        .iter()
        .filter_map(|tool| {
            tool.get("name")
                .and_then(|name| name.as_str())
                .map(|name| DiscoverMcpTool { name: name.to_string() })
        })
        .collect::<Vec<_>>();

    tools.sort_by(|left, right| left.name.cmp(&right.name));
    Ok(tools)
}

async fn send_discovery_request(
    client: &reqwest::Client,
    target_endpoint: &str,
    request: serde_json::Value,
    channel_name: &str,
    extra_headers: Option<&ReqwestHeaderMap>,
) -> Result<String, (StatusCode, String)> {
    let request_body = Bytes::from(request.to_string());
    // Discovery has no surface timeouts; the pinned client's
    // EXTERNAL_TIMEOUT_SECS already bounds the whole exchange.
    let limits = crate::proxy::upstream_body::UpstreamBodyLimits::new(
        crate::config::A2aConfig::default().max_body_size,
        None,
        crate::http_client::EXTERNAL_TIMEOUT_SECS,
    );

    match crate::mcp::sse_transport::send_mcp_request(
        client,
        target_endpoint,
        request_body.clone(),
        extra_headers,
        limits,
    )
    .await
    {
        Ok(crate::mcp::sse_transport::UpstreamMcpResponse::Json { status, body, .. }) => {
            if status.is_success() {
                return Ok(String::from_utf8_lossy(&body).to_string());
            }

            if matches!(status.as_u16(), 400 | 404 | 405) {
                return crate::mcp::sse_transport::send_via_persistent_sse(
                    client,
                    target_endpoint,
                    request_body.as_ref(),
                    channel_name,
                    crate::config::A2aConfig::default().max_body_size,
                )
                .await
                .map_err(|e| {
                    (StatusCode::BAD_GATEWAY, format!("Failed to communicate with MCP server over SSE: {}", e))
                });
            }

            Err((StatusCode::BAD_GATEWAY, format!("MCP server returned {}", status)))
        }
        Ok(crate::mcp::sse_transport::UpstreamMcpResponse::SseStream { status, response, .. }) => {
            if !status.is_success() {
                return Err((StatusCode::BAD_GATEWAY, format!("MCP server returned {}", status)));
            }

            crate::mcp::sse_transport::consume_sse_response(response, &request_body, limits)
                .await
                .map_err(|e| {
                    let status = match &e {
                        crate::mcp::sse_transport::SseConsumeError::Body(body_error) => {
                            body_error
                                .status_and_message()
                                .0
                        }
                        crate::mcp::sse_transport::SseConsumeError::NoResponse => StatusCode::BAD_GATEWAY,
                    };
                    (status, format!("Failed to read MCP SSE response: {}", e))
                })
        }
        Err(e) => Err((e.status_and_message().0, format!("Failed to reach MCP server: {}", e))),
    }
}

async fn build_discovery_headers(
    target_auth: Option<&DiscoverTargetAuthConfig>,
    secrets_store: &Option<Arc<dyn crate::secrets::SecretsStore>>,
    context: Option<&PatTenantContext>,
    scope: Option<&PatResourceScope>,
    channel_name: &str,
) -> Result<Option<ReqwestHeaderMap>, (StatusCode, String)> {
    let Some(target_auth) = target_auth.filter(|auth| auth.enabled) else {
        return Ok(None);
    };

    let backend_target_auth = to_backend_target_auth_config(target_auth)?;

    let crate::config::TargetAuthMethod::StaticSecret {
        secret_id,
        header_name,
        header_format,
    } = &backend_target_auth.method
    else {
        return Ok(None);
    };
    let store = secrets_store
        .as_ref()
        .ok_or_else(|| (StatusCode::INTERNAL_SERVER_ERROR, "Secrets store is not configured".to_string()))?;
    let secret = match store
        .get_by_secret_id(secret_id)
        .await
    {
        Ok(Some(secret)) => secret,
        Ok(None) => {
            return discovery_auth_resolution_failure(
                &backend_target_auth,
                channel_name,
                format!("Secret with secret_id '{secret_id}' not found"),
            );
        }
        Err(error) => {
            return discovery_auth_resolution_failure(
                &backend_target_auth,
                channel_name,
                format!("Failed to load secret '{secret_id}': {error}"),
            );
        }
    };
    if !discovery_secret_allowed(secret.tenant_id.as_deref(), &secret.secret_id, context, scope) {
        return Err((StatusCode::BAD_REQUEST, "Target auth secret is not accessible".to_string()));
    }

    let mut headers = ReqwestHeaderMap::new();
    let header_name = HeaderName::try_from(header_name.as_str())
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid target auth header name: {e}")))?;
    let header_value = HeaderValue::try_from(header_format.replace("{value}", &secret.value))
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid target auth header value: {e}")))?;
    headers.insert(header_name, header_value);
    debug!(channel = channel_name, secret_id = %secret_id, "Resolved authorized target auth secret");
    Ok(Some(headers))
}

fn discovery_auth_resolution_failure(
    target_auth: &crate::config::TargetAuthConfig,
    channel_name: &str,
    error: String,
) -> Result<Option<ReqwestHeaderMap>, (StatusCode, String)> {
    match target_auth.fallback {
        crate::config::TargetAuthFallback::Reject => {
            Err((StatusCode::BAD_GATEWAY, format!("Failed to resolve target auth for MCP discovery: {error}")))
        }
        crate::config::TargetAuthFallback::Passthrough => {
            warn!(channel = channel_name, %error, "Proceeding with MCP discovery without target auth due to passthrough fallback");
            Ok(None)
        }
    }
}

fn to_backend_target_auth_config(
    target_auth: &DiscoverTargetAuthConfig
) -> Result<crate::config::TargetAuthConfig, (StatusCode, String)> {
    let method = target_auth
        .method
        .as_deref()
        .unwrap_or("static_secret");
    if method != "static_secret" {
        return Err((StatusCode::BAD_REQUEST, format!("Unsupported target auth method for MCP discovery: {}", method)));
    }

    let secret_id = target_auth
        .secret_id
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| (StatusCode::BAD_REQUEST, "Target auth secret_id is required for MCP discovery".to_string()))?;

    let fallback = match target_auth
        .fallback
        .as_deref()
        .unwrap_or("reject")
    {
        "reject" => crate::config::TargetAuthFallback::Reject,
        "passthrough" => crate::config::TargetAuthFallback::Passthrough,
        other => {
            return Err((
                StatusCode::BAD_REQUEST,
                format!("Unsupported target auth fallback for MCP discovery: {}", other),
            ));
        }
    };

    Ok(crate::config::TargetAuthConfig {
        method: crate::config::TargetAuthMethod::StaticSecret {
            secret_id: secret_id.to_string(),
            header_name: target_auth
                .header_name
                .clone()
                .unwrap_or_else(|| "Authorization".to_string()),
            header_format: target_auth
                .header_format
                .clone()
                .unwrap_or_else(|| "{value}".to_string()),
        },
        auth_type: None,
        target_identifier: None,
        fallback,
    })
}

fn ensure_jsonrpc_success(response: &str) -> Result<serde_json::Value, (StatusCode, String)> {
    if response.trim().is_empty() {
        return Ok(serde_json::json!({}));
    }

    let response_json: serde_json::Value = serde_json::from_str(response)
        .map_err(|e| (StatusCode::BAD_GATEWAY, format!("MCP server returned invalid JSON: {}", e)))?;

    if let Some(error) = response_json.get("error") {
        let message = error
            .get("message")
            .and_then(|message| message.as_str())
            .unwrap_or("Unknown MCP error");
        return Err((StatusCode::BAD_GATEWAY, format!("MCP server returned an error: {}", message)));
    }

    Ok(response_json)
}

/// The proxy's `mcp_http.authorization.resource` must be its own public URL
/// (an inbound public origin plus `channel_prefix` + `endpoint_path`), and no
/// other stored surface or MCP Proxy may serve it
/// (`crate::sts::resource_owners`).
async fn ensure_proxy_may_declare_resource(
    owners: &crate::sts::resource_owners::ApplianceResourceOwners,
    proxy: &McpProxy,
) -> Result<(), (StatusCode, String)> {
    use crate::sts::resource_owners::{ResourceDeclarationError, ResourceEndpoint};
    let declarations: Vec<_> = crate::mcp::resource_server::proxy_resource_declaration(proxy, owners.network())
        .into_iter()
        .collect();
    owners
        .ensure_endpoint_may_declare(&ResourceEndpoint::McpProxy(proxy.id.clone()), &declarations)
        .await
        .map_err(|error| match error {
            ResourceDeclarationError::Unavailable => (StatusCode::INTERNAL_SERVER_ERROR, error.to_string()),
            _ => (StatusCode::BAD_REQUEST, error.to_string()),
        })
}

/// Create a new MCP Proxy
pub async fn create_mcp_proxy<S: McpProxyStore>(
    Extension(store): Extension<Arc<S>>,
    Extension(manager): Extension<Arc<McpServerManager>>,
    Extension(notification_store): Extension<Option<Arc<crate::integrations::FileSystemNotificationStore>>>,
    Extension(resource_owners): Extension<Arc<crate::sts::resource_owners::ApplianceResourceOwners>>,
    pat: Option<Extension<PatContext>>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
    Json(mut request): Json<CreateMcpProxyRequest>,
) -> Result<Json<McpProxyWriteResponse>, (StatusCode, String)> {
    request.tenant_id = tenant_for_create(request.tenant_id.take(), pat.is_some(), tenant_context(&context))
        .map_err(|message| (StatusCode::FORBIDDEN, message.to_string()))?;
    crate::config::enforce_add("proxies.mcp")
        .await
        .map_err(|e| (StatusCode::FORBIDDEN, e.message()))?;
    // Validate the endpoint path
    if !request
        .endpoint_path
        .starts_with('/')
    {
        return Err((StatusCode::BAD_REQUEST, "Endpoint path must start with '/'".to_string()));
    }

    // Block cloud-metadata and loopback URLs (SSRF protection)
    if let Err(e) = crate::url_validation::validate_resolved_url(&request.base_url) {
        return Err((StatusCode::BAD_REQUEST, e));
    }

    let requested_id = request.id.take();
    let managed_by = normalise_managed_by(request.managed_by.take())?;
    if let Some(id) = requested_id.as_deref()
        && !is_valid_mcp_proxy_id(id)
    {
        return Err((
            StatusCode::BAD_REQUEST,
            "MCP Proxy id must be 1-128 letters, digits, '-' or '_', starting with a letter or digit".to_string(),
        ));
    }

    // Create the MCP Proxy
    let mut proxy = McpProxy::new(
        request.name,
        request.description,
        request.base_url,
        request.openapi_spec,
        request.channel_prefix,
        request.endpoint_path,
    );
    proxy.tenant_id = request.tenant_id;
    if let Some(id) = requested_id {
        proxy.id = id;
    }
    if !scope_allows_resource(resource_scope(&scope), tenant_context(&context), ResourceKind::McpProxies, &proxy.id) {
        return Err((StatusCode::FORBIDDEN, "MCP Proxy is outside this token's permitted scope".into()));
    }
    // The store's create overwrites, so an existing id must be refused here or
    // a caller could replace someone else's proxy by naming it.
    if store
        .get(&proxy.id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .is_some()
    {
        return Err((StatusCode::CONFLICT, format!("MCP Proxy with ID '{}' already exists", proxy.id)));
    }
    proxy.flatten_post_params = request.flatten_post_params;
    proxy.direct_access = request
        .direct_access
        .unwrap_or(true);
    proxy.managed_by = managed_by;
    if let Some(config) = &request.mcp_http {
        config
            .validate()
            .map_err(|error| (StatusCode::BAD_REQUEST, error))?;
    }
    proxy.mcp_http = request.mcp_http;
    ensure_proxy_may_declare_resource(&resource_owners, &proxy).await?;

    // Try to create the MCP Server first
    let warnings = manager
        .create_server(&proxy)
        .await
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Failed to create MCP Server: {}", e)))?
        .into_iter()
        .collect();

    // Store the proxy
    store
        .create(&proxy)
        .await
        .map_err(|e| {
            // If storage fails, clean up the server
            let manager_clone = manager.clone();
            let proxy_id = proxy.id.clone();
            tokio::spawn(async move {
                manager_clone
                    .remove_server(&proxy_id)
                    .await;
            });
            (StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
        })?;

    // Trigger MCP proxy created event
    if let Some(ref notif_store) = notification_store {
        let proxy_clone = proxy.clone();
        let notif = notif_store.clone();
        tokio::spawn(async move {
            let status_str = match proxy_clone.status {
                crate::mcp_proxies::types::McpProxyStatus::Active => "Active".to_string(),
                crate::mcp_proxies::types::McpProxyStatus::Disabled => "Inactive".to_string(),
            };
            let mcp_proxy_trigger = crate::integrations::mcp_proxy_integration_triggers::McpProxy {
                id: proxy_clone.id.clone(),
                name: proxy_clone.name.clone(),
                description: proxy_clone
                    .description
                    .clone(),
                base_url: proxy_clone.base_url.clone(),
                channel_prefix: proxy_clone
                    .channel_prefix
                    .clone(),
                endpoint_path: proxy_clone
                    .endpoint_path
                    .clone(),
                status: status_str,
                created_at: Some(
                    proxy_clone
                        .created_at
                        .to_rfc3339(),
                ),
                updated_at: Some(
                    proxy_clone
                        .updated_at
                        .to_rfc3339(),
                ),
            };
            crate::integrations::mcp_proxy_integration_triggers::trigger_mcp_proxy_created(&notif, &mcp_proxy_trigger)
                .await;
        });
    }

    Ok(Json(McpProxyWriteResponse { proxy, warnings }))
}

/// Update an MCP Proxy
pub async fn update_mcp_proxy<S: McpProxyStore>(
    Extension(store): Extension<Arc<S>>,
    Extension(manager): Extension<Arc<McpServerManager>>,
    Extension(notification_store): Extension<Option<Arc<crate::integrations::FileSystemNotificationStore>>>,
    Extension(resource_owners): Extension<Arc<crate::sts::resource_owners::ApplianceResourceOwners>>,
    Path(id): Path<String>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
    Json(request): Json<UpdateMcpProxyRequest>,
) -> Result<Json<McpProxyWriteResponse>, (StatusCode, String)> {
    let mut proxy = store
        .get(&id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or_else(|| (StatusCode::NOT_FOUND, "MCP Proxy not found".to_string()))?;
    if !mcp_proxy_writable(&proxy, tenant_context(&context), resource_scope(&scope)) {
        return Err((StatusCode::FORBIDDEN, "MCP Proxy is outside this token's permitted scope".into()));
    }

    let old_proxy = proxy.clone();

    let mut needs_reload = false;

    // Update fields
    if let Some(name) = request.name {
        proxy.name = name;
    }
    if let Some(description) = request.description {
        proxy.description = description;
    }
    if let Some(base_url) = request.base_url {
        // Block cloud-metadata and loopback URLs (SSRF protection)
        if let Err(e) = crate::url_validation::validate_resolved_url(&base_url) {
            return Err((StatusCode::BAD_REQUEST, e));
        }
        proxy.base_url = base_url;
        needs_reload = true;
    }
    if let Some(openapi_spec) = request.openapi_spec {
        proxy.openapi_spec = openapi_spec;
        needs_reload = true;
    }
    if let Some(status) = request.status {
        proxy.status = status;
    }
    if let Some(channel_prefix) = request.channel_prefix {
        proxy.channel_prefix = channel_prefix;
    }
    if let Some(endpoint_path) = request.endpoint_path {
        if !endpoint_path.starts_with('/') {
            return Err((StatusCode::BAD_REQUEST, "Endpoint path must start with '/'".to_string()));
        }
        proxy.endpoint_path = endpoint_path;
    }
    if let Some(flatten_post_params) = request.flatten_post_params {
        proxy.flatten_post_params = flatten_post_params;
    }
    if let Some(direct_access) = request.direct_access {
        proxy.direct_access = direct_access;
    }
    if request.managed_by.is_some() {
        proxy.managed_by = normalise_managed_by(request.managed_by)?;
    }
    if let Some(config) = request.mcp_http {
        config
            .validate()
            .map_err(|error| (StatusCode::BAD_REQUEST, error))?;
        proxy.mcp_http = Some(config);
    }
    // Also re-checked when only the path changes: the kept resource must
    // still be this proxy's own URL.
    ensure_proxy_may_declare_resource(&resource_owners, &proxy).await?;

    proxy.updated_at = chrono::Utc::now();

    // Reload the MCP Server if needed
    let warning = if needs_reload {
        manager
            .reload_server(&proxy)
            .await
            .map_err(|e| (StatusCode::BAD_REQUEST, format!("Failed to reload MCP Server: {}", e)))?
    } else {
        manager
            .catalog_warning(&proxy.id)
            .await
    };
    let warnings = warning
        .into_iter()
        .collect::<Vec<_>>();

    store
        .update(&proxy)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // Trigger MCP proxy updated event
    if let Some(ref notif_store) = notification_store {
        let old_proxy_clone = old_proxy.clone();
        let new_proxy_clone = proxy.clone();
        let notif = notif_store.clone();
        tokio::spawn(async move {
            let old_status_str = match old_proxy_clone.status {
                crate::mcp_proxies::types::McpProxyStatus::Active => "Active".to_string(),
                crate::mcp_proxies::types::McpProxyStatus::Disabled => "Inactive".to_string(),
            };
            let new_status_str = match new_proxy_clone.status {
                crate::mcp_proxies::types::McpProxyStatus::Active => "Active".to_string(),
                crate::mcp_proxies::types::McpProxyStatus::Disabled => "Inactive".to_string(),
            };
            let old_mcp_proxy = crate::integrations::mcp_proxy_integration_triggers::McpProxy {
                id: old_proxy_clone.id.clone(),
                name: old_proxy_clone.name.clone(),
                description: old_proxy_clone
                    .description
                    .clone(),
                base_url: old_proxy_clone
                    .base_url
                    .clone(),
                channel_prefix: old_proxy_clone
                    .channel_prefix
                    .clone(),
                endpoint_path: old_proxy_clone
                    .endpoint_path
                    .clone(),
                status: old_status_str,
                created_at: Some(
                    old_proxy_clone
                        .created_at
                        .to_rfc3339(),
                ),
                updated_at: Some(
                    old_proxy_clone
                        .updated_at
                        .to_rfc3339(),
                ),
            };
            let new_mcp_proxy = crate::integrations::mcp_proxy_integration_triggers::McpProxy {
                id: new_proxy_clone.id.clone(),
                name: new_proxy_clone.name.clone(),
                description: new_proxy_clone
                    .description
                    .clone(),
                base_url: new_proxy_clone
                    .base_url
                    .clone(),
                channel_prefix: new_proxy_clone
                    .channel_prefix
                    .clone(),
                endpoint_path: new_proxy_clone
                    .endpoint_path
                    .clone(),
                status: new_status_str,
                created_at: Some(
                    new_proxy_clone
                        .created_at
                        .to_rfc3339(),
                ),
                updated_at: Some(
                    new_proxy_clone
                        .updated_at
                        .to_rfc3339(),
                ),
            };
            crate::integrations::mcp_proxy_integration_triggers::trigger_mcp_proxy_updated(
                &notif,
                &old_mcp_proxy,
                &new_mcp_proxy,
            )
            .await;
        });
    }

    Ok(Json(McpProxyWriteResponse { proxy, warnings }))
}

/// Delete an MCP Proxy
pub async fn delete_mcp_proxy<S: McpProxyStore>(
    Extension(store): Extension<Arc<S>>,
    Extension(manager): Extension<Arc<McpServerManager>>,
    Extension(notification_store): Extension<Option<Arc<crate::integrations::FileSystemNotificationStore>>>,
    Path(id): Path<String>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
) -> Result<StatusCode, (StatusCode, String)> {
    // Check if the proxy exists
    let proxy = store
        .get(&id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or_else(|| (StatusCode::NOT_FOUND, "MCP Proxy not found".to_string()))?;
    if !mcp_proxy_writable(&proxy, tenant_context(&context), resource_scope(&scope)) {
        return Err((StatusCode::FORBIDDEN, "MCP Proxy is outside this token's permitted scope".into()));
    }

    // Remove the MCP Server
    manager
        .remove_server(&id)
        .await;

    // Delete from storage
    store
        .delete(&id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // Trigger MCP proxy deleted event
    if let Some(ref notif_store) = notification_store {
        let proxy_clone = proxy.clone();
        let notif = notif_store.clone();
        tokio::spawn(async move {
            let status_str = match proxy_clone.status {
                crate::mcp_proxies::types::McpProxyStatus::Active => "Active".to_string(),
                crate::mcp_proxies::types::McpProxyStatus::Disabled => "Inactive".to_string(),
            };
            let mcp_proxy_trigger = crate::integrations::mcp_proxy_integration_triggers::McpProxy {
                id: proxy_clone.id.clone(),
                name: proxy_clone.name.clone(),
                description: proxy_clone
                    .description
                    .clone(),
                base_url: proxy_clone.base_url.clone(),
                channel_prefix: proxy_clone
                    .channel_prefix
                    .clone(),
                endpoint_path: proxy_clone
                    .endpoint_path
                    .clone(),
                status: status_str,
                created_at: Some(
                    proxy_clone
                        .created_at
                        .to_rfc3339(),
                ),
                updated_at: Some(
                    proxy_clone
                        .updated_at
                        .to_rfc3339(),
                ),
            };
            crate::integrations::mcp_proxy_integration_triggers::trigger_mcp_proxy_deleted(&notif, &mcp_proxy_trigger)
                .await;
        });
    }

    Ok(StatusCode::NO_CONTENT)
}

/// Validate OpenAPI spec without creating a proxy
#[derive(Debug, Deserialize)]
pub struct ValidateSpecRequest {
    pub openapi_spec: String,
    pub base_url: String,
}

#[derive(Debug, Serialize)]
pub struct ValidateSpecResponse {
    pub valid: bool,
    pub error: Option<String>,
    pub tools_count: Option<usize>,
}

pub async fn validate_openapi_spec(
    Json(request): Json<ValidateSpecRequest>
) -> Result<Json<ValidateSpecResponse>, (StatusCode, String)> {
    // Try to parse the YAML
    let openapi_json: serde_json::Value = match serde_yaml::from_str(&request.openapi_spec) {
        Ok(json) => json,
        Err(e) => {
            return Ok(Json(ValidateSpecResponse {
                valid: false,
                error: Some(format!("Invalid YAML: {}", e)),
                tools_count: None,
            }));
        }
    };

    // Validate the base URL
    if let Err(e) = Url::parse(&request.base_url) {
        return Ok(Json(ValidateSpecResponse {
            valid: false,
            error: Some(format!("Invalid base URL: {}", e)),
            tools_count: None,
        }));
    }

    // Block cloud-metadata and loopback URLs (SSRF protection)
    if let Err(e) = crate::url_validation::validate_resolved_url(&request.base_url) {
        return Ok(Json(ValidateSpecResponse {
            valid: false,
            error: Some(e),
            tools_count: None,
        }));
    }

    // Try to build the server
    let base_url = Url::parse(&request.base_url).unwrap();
    let mut server = McpServer::builder()
        .openapi_spec(openapi_json)
        .base_url(base_url)
        .build();

    match server.load_openapi_spec() {
        Ok(_) => {
            // Count tools (we can't easily get this from rmcp-openapi, so estimate based on spec)
            Ok(Json(ValidateSpecResponse {
                valid: true,
                error: None,
                tools_count: Some(0), // rmcp-openapi doesn't expose tool count easily
            }))
        }
        Err(e) => Ok(Json(ValidateSpecResponse {
            valid: false,
            error: Some(format!("Failed to load OpenAPI spec: {}", e)),
            tools_count: None,
        })),
    }
}

/// Health check for MCP proxy routes (GET requests)
/// Returns route information without exposing sensitive details
/// NOTE: Superseded by `handle_mcp_get` which also handles SSE.
#[allow(dead_code)]
pub async fn handle_mcp_info<S: McpProxyStore>(
    Extension(store): Extension<Arc<S>>,
    Path(path): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    debug!("📋 MCP route info requested for path: {}", path);

    let normalized_path = if !path.starts_with('/') {
        format!("/{}", path)
    } else {
        path.clone()
    };

    // Try to find matching proxy (optional - just for route validation)
    let proxy_exists = match store.list_all().await {
        Ok(proxies) => proxies
            .iter()
            .any(|p| normalized_path.starts_with(&p.endpoint_path)),
        Err(_) => false,
    };

    Ok(Json(serde_json::json!({
        "status": "ok",
        "service": "MCP Proxy Gateway",
        "route": normalized_path,
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "protocol": "MCP JSON-RPC 2.0",
        "methods": ["POST"],
        "configured": proxy_exists,
        "message": if proxy_exists {
            "This is an MCP endpoint. Send JSON-RPC requests via POST with Content-Type: application/json"
        } else {
            "No MCP proxy configured for this path"
        },
        "example": {
            "method": "POST",
            "headers": {"Content-Type": "application/json"},
            "body": {"jsonrpc": "2.0", "method": "initialize", "id": 1, "params": {}}
        }
    })))
}

/// Handle MCP JSON-RPC requests for a specific proxy
/// This is the main endpoint that serves MCP requests to clients
/// NOTE: Superseded by `handle_mcp_post` which also handles SSE and Streamable HTTP.
#[allow(dead_code)]
pub async fn handle_mcp_request<S: McpProxyStore>(
    Extension(store): Extension<Arc<S>>,
    Extension(manager): Extension<Arc<McpServerManager>>,
    Path(path): Path<String>,
    Json(request): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    info!("📨 Received MCP request for path: {}", path);
    debug!("Request payload: {:?}", request);

    // Find the proxy that matches this path
    // Note: The path here is just the suffix after the channel prefix was stripped by routing
    // So we match against endpoint_path (which should start with /)
    let proxies = store
        .list_all()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let normalized_path = if !path.starts_with('/') {
        format!("/{}", path)
    } else {
        path.clone()
    };

    let proxy = proxies
        .iter()
        .find(|p| normalized_path.starts_with(&p.endpoint_path))
        .ok_or_else(|| {
            warn!("❌ No MCP proxy configured for path: {} (normalized: {})", path, normalized_path);
            (StatusCode::NOT_FOUND, format!("No MCP proxy configured for path: {}", path))
        })?;

    info!("✓ Found matching proxy: '{}' (ID: {})", proxy.name, proxy.id);

    // Check if proxy is active
    if proxy.status != super::types::McpProxyStatus::Active {
        warn!("❌ Proxy '{}' is disabled", proxy.name);
        return Err((StatusCode::SERVICE_UNAVAILABLE, "MCP proxy is disabled".to_string()));
    }

    // Get the MCP server for this proxy
    let server_arc = manager
        .get_server(&proxy.id)
        .await
        .ok_or_else(|| {
            error!("❌ MCP server not initialized for proxy '{}'", proxy.name);
            (StatusCode::INTERNAL_SERVER_ERROR, "MCP server not initialized".to_string())
        })?;

    // Handle the MCP request
    let server = server_arc.read().await;

    let method = request
        .get("method")
        .and_then(|m| m.as_str())
        .unwrap_or("unknown");
    let request_id = request.get("id").cloned();

    info!("🔧 Handling MCP method: {}", method);

    match method {
        "initialize" => {
            // Return server info from the MCP server
            // Note: In rmcp 0.24.5, we construct the server info manually
            // as get_info() requires trait bounds that aren't satisfied
            info!("✓ Returning initialize response for '{}'", proxy.name);

            Ok(Json(serde_json::json!({
                "jsonrpc": "2.0",
                "id": request_id,
                "result": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {
                        "tools": {}
                    },
                    "serverInfo": {
                        "name": proxy.name.clone(),
                        "version": "1.0.0"
                    }
                }
            })))
        }
        "tools/list" => {
            // Get tool names from the server
            let tool_names = server.get_tool_names();
            info!("✓ Found {} tools for proxy '{}'", tool_names.len(), proxy.name);

            // Get full tool metadata
            let mut tools = Vec::new();
            for tool_name in tool_names {
                if let Some(metadata) = server.get_tool_metadata(&tool_name) {
                    let input_schema = if proxy.flatten_post_params {
                        flatten_input_schema(&metadata.parameters)
                    } else {
                        metadata.parameters.clone()
                    };
                    tools.push(serde_json::json!({
                        "name": metadata.name,
                        "description": metadata.description,
                        "inputSchema": input_schema,
                    }));
                    debug!("  - Tool: {}", metadata.name);
                }
            }

            Ok(Json(serde_json::json!({
                "jsonrpc": "2.0",
                "id": request_id,
                "result": {
                    "tools": tools
                }
            })))
        }
        "tools/call" => {
            // Extract tool name and arguments from the request
            let params = request
                .get("params")
                .ok_or_else(|| {
                    error!("❌ Missing 'params' in tools/call request");
                    (StatusCode::BAD_REQUEST, "Missing 'params' in tools/call request".to_string())
                })?;

            let tool_name = params
                .get("name")
                .and_then(|n| n.as_str())
                .ok_or_else(|| {
                    error!("❌ Missing 'name' in tools/call params");
                    (StatusCode::BAD_REQUEST, "Missing tool 'name' in params".to_string())
                })?;

            let raw_arguments = params
                .get("arguments")
                .cloned()
                .unwrap_or(serde_json::json!({}));

            // Auto-wrap flat arguments into request_body if the tool expects it (only when flattening is enabled)
            let arguments = if proxy.flatten_post_params {
                wrap_request_body_if_needed(&server, tool_name, raw_arguments)
            } else {
                raw_arguments
            };

            info!("🔨 Calling tool: {} with args: {:?}", tool_name, arguments);

            // Get the tool and call it
            let tool = server
                .get_tool(tool_name)
                .ok_or_else(|| {
                    error!("❌ Tool '{}' not found", tool_name);
                    (StatusCode::NOT_FOUND, format!("Tool '{}' not found", tool_name))
                })?;

            // Call the tool (this will make the actual HTTP request to the backend API)
            // The tool.call method requires: arguments, authorization, and optional response transformer
            use rmcp_openapi::Authorization;
            match tool
                .call(&arguments, Authorization::None, None)
                .await
            {
                Ok(result) => {
                    info!("✓ Tool '{}' executed successfully", tool_name);
                    debug!("Result: {:?}", result);

                    // Extract content from CallToolResult
                    let content = result.content;

                    Ok(Json(serde_json::json!({
                        "jsonrpc": "2.0",
                        "id": request_id,
                        "result": {
                            "content": content,
                            "isError": result.is_error
                        }
                    })))
                }
                Err(e) => {
                    error!("❌ Tool '{}' execution failed: {}", tool_name, e);
                    Err((StatusCode::INTERNAL_SERVER_ERROR, format!("Tool execution failed: {}", e)))
                }
            }
        }
        _ => {
            warn!("❌ Unknown MCP method: {}", method);
            Err((StatusCode::BAD_REQUEST, format!("Unknown MCP method: {}", method)))
        }
    }
}

// ─── SSE transport handlers ─────────────────────────────────────────────────

/// Find the matching proxy for a path and return it along with the path suffix.
///
/// Returns `(proxy, suffix)` where suffix is the rest of the path after `endpoint_path`,
/// e.g. for path `/eternal/dilemma/sse` and endpoint_path `/eternal/dilemma`, suffix is `/sse`.
async fn find_proxy_for_path<S: McpProxyStore>(
    store: &S,
    path: &str,
) -> Result<(McpProxy, String), (StatusCode, String)> {
    let normalized_path = if !path.starts_with('/') {
        format!("/{}", path)
    } else {
        path.to_string()
    };

    let proxies = store
        .list_all()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let proxy = proxies
        .into_iter()
        .filter(|p| p.direct_access && endpoint_path_matches(&normalized_path, &p.endpoint_path))
        .max_by_key(|p| p.endpoint_path.len())
        .ok_or_else(|| (StatusCode::NOT_FOUND, format!("No MCP proxy configured for path: {}", path)))?;

    let suffix = normalized_path[proxy.endpoint_path.len()..].to_string();
    Ok((proxy, suffix))
}

/// Whether `path` addresses the proxy at `endpoint_path`, on a path-segment
/// boundary so `/foo` does not also answer `/foobar`.
fn endpoint_path_matches(
    path: &str,
    endpoint_path: &str,
) -> bool {
    match path.strip_prefix(endpoint_path) {
        Some(rest) => rest.is_empty() || rest.starts_with('/') || endpoint_path.ends_with('/'),
        None => false,
    }
}

/// Process a JSON-RPC request against a proxy and return the response as a JSON value.
///
/// This is a shared core used by both the sync handler and the SSE handlers.
async fn process_mcp_request_core(
    proxy: &McpProxy,
    manager: &McpServerManager,
    request: &serde_json::Value,
    inbound_headers: Option<&HeaderMap>,
) -> Result<serde_json::Value, (StatusCode, String)> {
    if proxy.status != super::types::McpProxyStatus::Active {
        return Err((StatusCode::SERVICE_UNAVAILABLE, "MCP proxy is disabled".to_string()));
    }

    let server_arc = manager
        .get_server(&proxy.id)
        .await
        .ok_or_else(|| (StatusCode::INTERNAL_SERVER_ERROR, "MCP server not initialized".to_string()))?;

    let server = server_arc.read().await;

    let method = request
        .get("method")
        .and_then(|m| m.as_str())
        .unwrap_or("unknown");
    let request_id = request.get("id").cloned();

    info!("🔧 Handling MCP method: {}", method);

    match method {
        "initialize" => Ok(serde_json::json!({
            "jsonrpc": "2.0",
            "id": request_id,
            "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": { "tools": {} },
                "serverInfo": {
                    "name": proxy.name.clone(),
                    "version": "1.0.0"
                }
            }
        })),
        "notifications/initialized" => {
            // Notification — no response needed (JSON-RPC notifications have no id)
            Ok(serde_json::json!(null))
        }
        "tools/list" => {
            let tool_names = server.get_tool_names();
            let mut tools = Vec::new();
            for tool_name in tool_names {
                if let Some(metadata) = server.get_tool_metadata(&tool_name) {
                    let input_schema = if proxy.flatten_post_params {
                        flatten_input_schema(&metadata.parameters)
                    } else {
                        metadata.parameters.clone()
                    };
                    tools.push(serde_json::json!({
                        "name": metadata.name,
                        "description": metadata.description,
                        "inputSchema": input_schema,
                    }));
                }
            }
            Ok(serde_json::json!({
                "jsonrpc": "2.0",
                "id": request_id,
                "result": { "tools": tools }
            }))
        }
        "tools/call" => {
            let params = request
                .get("params")
                .ok_or_else(|| (StatusCode::BAD_REQUEST, "Missing 'params' in tools/call request".to_string()))?;
            let tool_name = params
                .get("name")
                .and_then(|n| n.as_str())
                .ok_or_else(|| (StatusCode::BAD_REQUEST, "Missing tool 'name' in params".to_string()))?;
            let raw_arguments = params
                .get("arguments")
                .cloned()
                .unwrap_or(serde_json::json!({}));
            let arguments = if proxy.flatten_post_params {
                wrap_request_body_if_needed(&server, tool_name, raw_arguments)
            } else {
                raw_arguments
            };

            // If inbound headers are present, build a temporary server with those
            // headers so the upstream REST calls carry them (e.g. X-API-Key).
            // Re-uses the already-parsed JSON from the cached server to avoid
            // re-parsing the YAML spec on every request.
            let temp_server;
            let effective_server: &McpServer = if let Some(hdrs) = inbound_headers {
                let forwarded = extract_forwardable_headers(hdrs);
                if !forwarded.is_empty() {
                    let base_url = Url::parse(&proxy.base_url)
                        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Invalid base URL: {}", e)))?;
                    let mut s = McpServer::builder()
                        .openapi_spec(server.openapi_spec.clone())
                        .base_url(base_url)
                        .default_headers(forwarded)
                        .build();
                    s.load_openapi_spec()
                        .map_err(|e| {
                            (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to load OpenAPI spec: {}", e))
                        })?;
                    temp_server = s;
                    &temp_server
                } else {
                    &server
                }
            } else {
                &server
            };

            let tool = effective_server
                .get_tool(tool_name)
                .ok_or_else(|| (StatusCode::NOT_FOUND, format!("Tool '{}' not found", tool_name)))?;

            use rmcp_openapi::Authorization;
            match tool
                .call(&arguments, Authorization::None, None)
                .await
            {
                Ok(result) => Ok(serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "result": {
                        "content": result.content,
                        "isError": result.is_error
                    }
                })),
                Err(e) => {
                    error!("❌ Tool '{}' execution failed: {}", tool_name, e);
                    Err((StatusCode::INTERNAL_SERVER_ERROR, format!("Tool execution failed: {}", e)))
                }
            }
        }
        _ => Err((StatusCode::BAD_REQUEST, format!("Unknown MCP method: {}", method))),
    }
}

/// The egress allow-list for an owned MCP Proxy's REST backend: the BDD
/// allow-list in production, and the proxy's own loopback fixture in unit
/// tests, whose refusal without it is covered by `modern_rest` and `egress`.
fn rest_egress_allowlist(proxy: &McpProxy) -> Option<String> {
    if cfg!(test) {
        return Some(proxy.base_url.clone());
    }
    crate::egress::bdd_egress_allowlist()
}

#[cfg(test)]
async fn process_modern_mcp_request(
    proxy: &McpProxy,
    manager: &McpServerManager,
    request: &crate::mcp::request_validation::ValidatedModernMessage,
    versions: crate::mcp::request_validation::McpVersionPolicy<'_>,
) -> Result<serde_json::Value, Box<crate::mcp::request_validation::McpRequestValidationError>> {
    process_modern_mcp_request_with_headers(proxy, manager, request, versions, &HeaderMap::new(), None).await
}

async fn process_modern_mcp_request_with_headers(
    proxy: &McpProxy,
    manager: &McpServerManager,
    request: &crate::mcp::request_validation::ValidatedModernMessage,
    versions: crate::mcp::request_validation::McpVersionPolicy<'_>,
    request_headers: &HeaderMap,
    target_headers: Option<&HeaderMap>,
) -> Result<serde_json::Value, Box<crate::mcp::request_validation::McpRequestValidationError>> {
    use crate::mcp::error_codes;
    use crate::mcp::modern::{complete_response, owned_discovery_response, require_active_version};
    use crate::mcp::request_validation::{McpMessageKind, McpRequestValidationError};

    require_active_version(request, versions)?;
    let failure = |status, code, message: &str| {
        Box::new(McpRequestValidationError {
            status,
            id: request.id.clone(),
            code,
            message: message.to_string(),
            data: None,
        })
    };
    if request.kind != McpMessageKind::Request
        || !matches!(request.method.as_str(), "server/discover" | "tools/list" | "tools/call")
    {
        return Err(failure(
            StatusCode::NOT_FOUND,
            error_codes::METHOD_NOT_FOUND,
            "MCP method is not implemented by this proxy",
        ));
    }
    if proxy.status != super::types::McpProxyStatus::Active {
        return Err(failure(StatusCode::SERVICE_UNAVAILABLE, error_codes::INTERNAL_ERROR, "MCP proxy is unavailable"));
    }
    let catalogs = manager
        .get_catalogs(&proxy.id)
        .await
        .ok_or_else(|| {
            failure(StatusCode::SERVICE_UNAVAILABLE, error_codes::INTERNAL_ERROR, "MCP tool catalog is unavailable")
        })?;
    if request.method == "server/discover" {
        let mut response = owned_discovery_response(request, versions, &proxy.name, env!("CARGO_PKG_VERSION"))?;
        if catalogs.legacy.is_none()
            && let Some(supported) = response["result"]["supportedVersions"].as_array_mut()
        {
            supported.retain(|version| version.as_str() != Some(crate::mcp::MCP_LEGACY_VERSION));
        }
        return Ok(response);
    }
    let server = catalogs.modern;
    if request.method == "tools/call" {
        let params = request
            .params
            .as_ref()
            .and_then(serde_json::Value::as_object)
            .ok_or_else(|| {
                failure(StatusCode::BAD_REQUEST, error_codes::INVALID_PARAMS, "tools/call requires params")
            })?;
        let name = params
            .get("name")
            .and_then(serde_json::Value::as_str)
            .filter(|name| !name.is_empty())
            .ok_or_else(|| {
                failure(StatusCode::BAD_REQUEST, error_codes::INVALID_PARAMS, "tools/call requires a tool name")
            })?;
        let arguments = params
            .get("arguments")
            .cloned()
            .unwrap_or_else(|| serde_json::json!({}));
        if !arguments.is_object() {
            return Err(failure(
                StatusCode::BAD_REQUEST,
                error_codes::INVALID_PARAMS,
                "Tool arguments must be an object",
            ));
        }
        let (tool, arguments, content_type) = {
            let server = server.read().await;
            let mut tool = server
                .get_tool(name)
                .cloned()
                .ok_or_else(|| failure(StatusCode::BAD_REQUEST, error_codes::INVALID_PARAMS, "Tool was not found"))?;
            let schema =
                modern_tool_input_schema(&server, &tool.metadata, proxy.flatten_post_params).map_err(|_| {
                    failure(
                        StatusCode::BAD_REQUEST,
                        error_codes::INVALID_PARAMS,
                        "Tool schema cannot be safely transformed",
                    )
                })?;
            let bindings = crate::mcp::tool_headers::ToolHeaderBindings::compile(&schema).map_err(|error| {
                warn!(proxy_id = %proxy.id, tool = %name, error = %error, "Invalid MCP tool header annotations");
                failure(StatusCode::BAD_REQUEST, error_codes::INVALID_PARAMS, "Tool has invalid header annotations")
            })?;
            bindings.validate(&arguments, request_headers, request.id.clone())?;
            let validator = super::modern_rest::compile_schema(&schema).map_err(|_| {
                failure(StatusCode::BAD_REQUEST, error_codes::INVALID_PARAMS, "Tool schema cannot be validated offline")
            })?;
            if !validator.is_valid(&arguments) {
                return Err(failure(StatusCode::BAD_REQUEST, error_codes::INVALID_PARAMS, "Invalid tool arguments"));
            }
            if proxy.flatten_post_params
                && arguments
                    .get("request_body")
                    .is_some()
            {
                return Err(failure(
                    StatusCode::BAD_REQUEST,
                    error_codes::INVALID_PARAMS,
                    "Flattened tools require flat arguments",
                ));
            }
            let arguments = if proxy.flatten_post_params {
                wrap_request_body_if_needed(&server, name, arguments)
            } else {
                arguments
            };
            let content_type =
                super::modern_rest::request_content_type(&server.openapi_spec, &tool.metadata).map_err(|_| {
                    failure(
                        StatusCode::BAD_REQUEST,
                        error_codes::INVALID_PARAMS,
                        "Tool request body cannot be safely encoded",
                    )
                })?;
            tool.metadata.output_schema = super::modern_rest::output_schema(&server.openapi_spec, &tool.metadata)
                .map_err(|_| {
                    failure(
                        StatusCode::BAD_REQUEST,
                        error_codes::INVALID_PARAMS,
                        "Tool output schema cannot be validated offline",
                    )
                })?;
            (tool, arguments, content_type)
        };
        crate::url_validation::reject_cloud_metadata_url(&proxy.base_url).map_err(|_| {
            failure(StatusCode::BAD_GATEWAY, error_codes::INTERNAL_ERROR, "MCP proxy target is not permitted")
        })?;
        let config = proxy
            .mcp_http
            .clone()
            .unwrap_or_default();
        let target_headers = if let Some(headers) = target_headers {
            let mut forwarded = extract_forwardable_headers(headers);
            let names: Vec<_> = forwarded
                .keys()
                .filter(|name| {
                    name.as_str()
                        .starts_with("mcp-")
                        || name.as_str() == "last-event-id"
                })
                .cloned()
                .collect();
            for name in names {
                forwarded.remove(name);
            }
            forwarded
        } else {
            HeaderMap::new()
        };
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(
                config
                    .stream_max_lifetime_secs
                    .get(),
            ),
            super::modern_rest::call(
                &proxy.base_url,
                &tool.metadata,
                &arguments,
                &target_headers,
                &config,
                &content_type,
                rest_egress_allowlist(proxy).as_deref(),
            ),
        )
        .await
        .map_err(|_| {
            failure(StatusCode::GATEWAY_TIMEOUT, error_codes::INTERNAL_ERROR, "MCP tool execution timed out")
        })?;
        let fields = match result {
            Ok(result) => serde_json::to_value(result).map_err(|_| {
                failure(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    error_codes::INTERNAL_ERROR,
                    "Failed to serialize tool result",
                )
            })?,
            Err(super::modern_rest::RestError::Arguments) => {
                return Err(failure(StatusCode::BAD_REQUEST, error_codes::INVALID_PARAMS, "Invalid tool arguments"));
            }
            Err(super::modern_rest::RestError::Execution) => {
                warn!(proxy_id = %proxy.id, tool = %name, "Modern MCP tool execution failed");
                serde_json::json!({"isError": true, "content": [{"type": "text", "text": "Tool execution failed"}]})
            }
            Err(error) => {
                return Err(failure(StatusCode::BAD_GATEWAY, error_codes::INTERNAL_ERROR, &error.to_string()));
            }
        };
        let fields = fields
            .as_object()
            .cloned()
            .ok_or_else(|| {
                failure(StatusCode::INTERNAL_SERVER_ERROR, error_codes::INTERNAL_ERROR, "Invalid tool result")
            })?;
        let response = complete_response(request, fields).map_err(|_| {
            failure(StatusCode::INTERNAL_SERVER_ERROR, error_codes::INTERNAL_ERROR, "Failed to build tool result")
        })?;
        if serde_json::to_vec(&response).map_or(true, |bytes| {
            bytes.len()
                > config
                    .max_response_bytes
                    .get()
        }) {
            return Err(failure(
                StatusCode::BAD_GATEWAY,
                error_codes::INTERNAL_ERROR,
                "MCP tool result exceeds the configured limit",
            ));
        }
        return Ok(response);
    }
    if request
        .params
        .as_ref()
        .is_some_and(|params| params.get("cursor").is_some())
    {
        return Err(failure(
            StatusCode::BAD_REQUEST,
            error_codes::INVALID_PARAMS,
            "This tool catalog does not use pagination cursors",
        ));
    }
    let server = server.read().await;
    let mut names = server.get_tool_names();
    names.sort();
    let mut tools = Vec::with_capacity(names.len());
    for name in names {
        let Some(metadata) = server.get_tool_metadata(&name) else { continue };
        let schema = match modern_tool_input_schema(&server, metadata, proxy.flatten_post_params) {
            Ok(schema) => schema,
            Err(error) => {
                warn!(proxy_id = %proxy.id, tool = %name, error = %error, "Exclude tool with invalid MCP schema transformation or header annotations");
                continue;
            }
        };
        let mut tool = serde_json::json!({
            "name": metadata.name,
            "inputSchema": schema,
        });
        if let Some(title) = &metadata.title {
            tool["title"] = serde_json::json!(title);
        }
        if let Some(description) = &metadata.description {
            tool["description"] = serde_json::json!(description);
        }
        match super::modern_rest::output_schema(&server.openapi_spec, metadata) {
            Ok(Some(schema)) => tool["outputSchema"] = schema,
            Ok(None) => {}
            Err(error) => {
                warn!(proxy_id = %proxy.id, tool = %name, error = %error, "Exclude tool with an invalid output schema");
                continue;
            }
        }
        if let Some(annotations) = metadata.generate_annotations() {
            tool["annotations"] = serde_json::json!(annotations);
        }
        tools.push(tool);
    }
    let mut fields = serde_json::Map::new();
    fields.insert("tools".to_string(), serde_json::Value::Array(tools));
    complete_response(request, fields).map_err(|_| {
        failure(
            StatusCode::INTERNAL_SERVER_ERROR,
            error_codes::INTERNAL_ERROR,
            "Failed to build MCP tool catalog response",
        )
    })
}

pub(crate) async fn handle_modern_surface_http_request(
    proxy: &McpProxy,
    surface: &crate::config::agent_surface::AgentSurface,
    request: &crate::mcp::request_validation::ValidatedModernMessage,
    prepared: reqwest::Request,
    client: &reqwest::Client,
    versions: crate::mcp::request_validation::McpVersionPolicy<'_>,
) -> Result<axum::response::Response, Box<crate::mcp::request_validation::McpRequestValidationError>> {
    use axum::response::IntoResponse;
    if request.method == "subscriptions/listen" {
        let mut proxy = proxy.clone();
        proxy.mcp_http = surface.mcp_http.clone();
        return owned_modern_subscription(&proxy, request, versions);
    }
    let message = handle_modern_surface_request(proxy, surface, request, prepared, client, versions).await?;
    let mut response = Json(message).into_response();
    response
        .headers_mut()
        .insert("cache-control", axum::http::HeaderValue::from_static("no-store"));
    Ok(response)
}

pub(crate) async fn handle_modern_surface_request(
    proxy: &McpProxy,
    surface: &crate::config::agent_surface::AgentSurface,
    request: &crate::mcp::request_validation::ValidatedModernMessage,
    prepared: reqwest::Request,
    _client: &reqwest::Client,
    versions: crate::mcp::request_validation::McpVersionPolicy<'_>,
) -> Result<serde_json::Value, Box<crate::mcp::request_validation::McpRequestValidationError>> {
    crate::mcp::modern::require_active_version(request, versions)?;
    let mut proxy = proxy.clone();
    proxy.mcp_http = surface.mcp_http.clone();
    let manager = McpServerManager::new();
    manager
        .create_server(&proxy)
        .await
        .map_err(|error| {
            warn!(proxy_id = %proxy.id, error = %error, "Failed to prepare modern surface tools");
            Box::new(crate::mcp::request_validation::McpRequestValidationError {
                status: StatusCode::SERVICE_UNAVAILABLE,
                id: request.id.clone(),
                code: crate::mcp::error_codes::INTERNAL_ERROR,
                message: "MCP tool catalog is unavailable".to_string(),
                data: None,
            })
        })?;
    process_modern_mcp_request_with_headers(
        &proxy,
        &manager,
        request,
        versions,
        prepared.headers(),
        Some(prepared.headers()),
    )
    .await
}

/// Extract headers from an inbound request that should be forwarded to the
/// upstream REST backend. Skips hop-by-hop, host, content-length, and
/// internal gateway headers. Converts from axum `HeaderMap` to reqwest
/// `HeaderMap`.
fn extract_forwardable_headers(headers: &HeaderMap) -> ReqwestHeaderMap {
    let mut forwarded = ReqwestHeaderMap::new();
    for (key, value) in headers.iter() {
        let name = key.as_str().to_lowercase();
        // Skip hop-by-hop, content-length, host, and accept headers
        if matches!(
            name.as_str(),
            "connection"
                | "keep-alive"
                | "proxy-authenticate"
                | "proxy-authorization"
                | "te"
                | "trailers"
                | "transfer-encoding"
                | "upgrade"
                | "content-length"
                | "content-type"
                | "host"
                | "accept"
        ) {
            continue;
        }
        if let (Ok(header_name), Ok(header_value)) =
            (HeaderName::from_bytes(key.as_str().as_bytes()), HeaderValue::from_bytes(value.as_bytes()))
        {
            forwarded.insert(header_name, header_value);
        }
    }
    forwarded
}

/// GET handler for MCP proxy routes — supports both info and Legacy SSE.
///
/// - `GET .../sse` → Legacy SSE: creates a session, returns SSE stream
/// - `GET ...` (anything else) → route info / health check
pub async fn handle_mcp_get<S: McpProxyStore>(
    Extension(store): Extension<Arc<S>>,
    Extension(session_mgr): Extension<SseSessionManager>,
    Extension(network): Extension<Arc<crate::config::NetworkConfig>>,
    auth: Option<Extension<crate::mcp::resource_server::ResourceServerAuthContext>>,
    method: axum::http::Method,
    headers: HeaderMap,
    Path(path): Path<String>,
) -> Result<axum::response::Response, (StatusCode, String)> {
    let normalized_path = if !path.starts_with('/') {
        format!("/{}", path)
    } else {
        path.clone()
    };

    if let Ok((proxy, _)) = find_proxy_for_path(store.as_ref(), &normalized_path).await {
        if let Some(authorization) = proxy
            .mcp_http
            .as_ref()
            .and_then(|http| http.authorization.as_ref())
        {
            let Some(Extension(auth)) = &auth else {
                return Ok(authorization.challenge(crate::mcp::resource_server::ResourceTokenError::Unavailable));
            };
            if let Err(error) = auth
                .authenticate_proxy(&proxy, &network, &headers)
                .await
            {
                return Ok(authorization.challenge(error));
            }
        }
        let policy = crate::mcp::modern_http::EndpointHttpPolicy::new(
            proxy.mcp_http.as_ref(),
            &network.get_inbound_external_urls(),
            crate::mcp::request_validation::McpPathKind::OwnedProxy,
        )
        .map_err(|error| (StatusCode::INTERNAL_SERVER_ERROR, error))?;
        if let Err(error) = policy.validate_headers(&headers) {
            return Ok(error.into_response(None));
        }
        if let Some(response) = policy.non_post_response(&method, &headers) {
            return Ok(response);
        }
    }
    if method == axum::http::Method::DELETE {
        let mut response = axum::response::Response::new(axum::body::Body::empty());
        *response.status_mut() = StatusCode::METHOD_NOT_ALLOWED;
        response
            .headers_mut()
            .insert("allow", axum::http::HeaderValue::from_static("GET,HEAD,POST"));
        return Ok(response);
    }

    // Check if this is an SSE connect request
    if normalized_path.ends_with("/sse") {
        let base_path = &normalized_path[..normalized_path.len() - 4]; // strip "/sse"

        // Validate that a proxy exists for this path
        let proxy_exists = match store.list_all().await {
            Ok(proxies) => proxies
                .iter()
                .any(|p| p.direct_access && endpoint_path_matches(base_path, &p.endpoint_path)),
            Err(_) => false,
        };
        if !proxy_exists {
            return Err((StatusCode::NOT_FOUND, format!("No MCP proxy configured for path: {}", base_path)));
        }

        info!("🔌 SSE connect for MCP proxy at {}", base_path);
        let (session_id, rx_stream) = session_mgr
            .create_session()
            .await;
        let response = crate::mcp::sse_server::build_legacy_sse_response(session_id, rx_stream, base_path);
        return Ok(response);
    }

    // Fall through to info handler
    let proxy_exists = match store.list_all().await {
        Ok(proxies) => proxies
            .iter()
            .any(|p| p.direct_access && endpoint_path_matches(&normalized_path, &p.endpoint_path)),
        Err(_) => false,
    };

    let info_json = serde_json::json!({
        "status": "ok",
        "service": "MCP Proxy Gateway",
        "route": normalized_path,
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "protocol": "MCP JSON-RPC 2.0",
        "transport": ["json-rpc", "sse", "streamable-http"],
        "methods": ["GET /sse", "POST"],
        "configured": proxy_exists,
        "message": if proxy_exists {
            "This is an MCP endpoint. Connect via GET /sse for SSE transport, or POST with JSON-RPC."
        } else {
            "No MCP proxy configured for this path"
        }
    });

    Ok(axum::response::IntoResponse::into_response(axum::Json(info_json)))
}

/// POST handler for MCP proxy routes — supports sync JSON, SSE session messages,
/// and Streamable HTTP.
///
/// - `POST .../mcp/messages/?session_id=X` → Legacy SSE session message
/// - `POST ...` with `Accept: text/event-stream` → Streamable HTTP SSE response
/// - `POST ...` → synchronous JSON response (existing behaviour)
pub async fn handle_mcp_post<S: McpProxyStore>(
    Extension(store): Extension<Arc<S>>,
    Extension(manager): Extension<Arc<McpServerManager>>,
    Extension(session_mgr): Extension<SseSessionManager>,
    Extension(network): Extension<Arc<crate::config::NetworkConfig>>,
    auth: Option<Extension<crate::mcp::resource_server::ResourceServerAuthContext>>,
    mut headers: HeaderMap,
    axum::extract::OriginalUri(uri): axum::extract::OriginalUri,
    Path(path): Path<String>,
    request: axum::extract::Request,
) -> Result<axum::response::Response, (StatusCode, String)> {
    use axum::extract::FromRequest;
    use axum::response::IntoResponse;

    let mut subscription_access =
        crate::mcp::subscriptions::SubscriptionLifetime::new(std::time::Duration::from_secs(86_400), None);
    let normalized_path = if !path.starts_with('/') {
        format!("/{}", path)
    } else {
        path.clone()
    };

    let base_path = normalized_path
        .find("/mcp/messages")
        .map_or(normalized_path.as_str(), |index| &normalized_path[..index]);
    let (proxy, _suffix) = find_proxy_for_path(store.as_ref(), base_path).await?;
    subscription_access.record_proxy_owner(&proxy);
    if let Some(authorization) = proxy
        .mcp_http
        .as_ref()
        .and_then(|http| http.authorization.as_ref())
    {
        let Some(Extension(auth)) = &auth else {
            return Ok(authorization.challenge(crate::mcp::resource_server::ResourceTokenError::Unavailable));
        };
        match auth
            .authenticate_proxy(&proxy, &network, &headers)
            .await
        {
            Ok(identity) => subscription_access.restrict_to_identity(identity.as_ref()),
            Err(error) => return Ok(authorization.challenge(error)),
        }
        headers.remove(axum::http::header::AUTHORIZATION);
    }
    let policy = crate::mcp::modern_http::EndpointHttpPolicy::new(
        proxy.mcp_http.as_ref(),
        &network.get_inbound_external_urls(),
        crate::mcp::request_validation::McpPathKind::OwnedProxy,
    )
    .map_err(|error| (StatusCode::INTERNAL_SERVER_ERROR, error))?;
    if let Err(error) = policy.validate_headers(&headers) {
        return Ok(error.into_response(None));
    }
    let (parts, body) = request.into_parts();
    let body = match axum::body::to_bytes(body, policy.body_limit()).await {
        Ok(body) => body,
        Err(error) => return Ok((*policy.body_read_error(error)).into_response()),
    };
    let session = if headers.contains_key("mcp-session-id") || normalized_path.contains("/mcp/messages") {
        crate::mcp::request_validation::LegacySessionEvidence::Unknown
    } else {
        crate::mcp::request_validation::LegacySessionEvidence::Absent
    };
    let classification = match policy.admit_post(&headers, &body, session) {
        Ok(classification) => classification,
        Err(error) => return Ok((*error).into_response()),
    };
    if let crate::mcp::request_validation::McpRequestClassification::Modern(request) = classification {
        let response = owned_modern_http_response(
            &proxy,
            &manager,
            &request,
            crate::mcp::request_validation::runtime_policy_for(crate::mcp::request_validation::McpPathKind::OwnedProxy),
            &headers,
        )
        .await;
        return Ok(if request.method == "subscriptions/listen" && response.status().is_success() {
            subscription_access.restrict_lifetime(std::time::Duration::from_secs(
                proxy
                    .mcp_http
                    .clone()
                    .unwrap_or_default()
                    .stream_max_lifetime_secs
                    .get(),
            ));
            subscription_access.wrap(response)
        } else {
            response
        });
    }
    let parsed = Json::<serde_json::Value>::from_request(
        axum::http::Request::from_parts(parts, axum::body::Body::from(body)),
        &(),
    )
    .await;
    let Json(request) = match parsed {
        Ok(request) => request,
        Err(error) => return Ok(error.into_response()),
    };

    // ── Legacy SSE session message ──────────────────────────────────────────
    // Path looks like .../mcp/messages/ with ?session_id=X
    if normalized_path.contains("/mcp/messages") {
        let session_id = crate::mcp::sse_server::extract_session_id(uri.query())
            .ok_or_else(|| (StatusCode::BAD_REQUEST, "Missing session_id query parameter".to_string()))?;

        if !session_mgr
            .session_exists(&session_id)
            .await
        {
            return Err((StatusCode::NOT_FOUND, format!("SSE session '{}' not found or expired", session_id)));
        }

        info!("📨 SSE session message for proxy '{}' session={}", proxy.name, session_id);

        // Check if this is a notification (no id → no response expected)
        let is_notification = request.get("id").is_none();

        let response = process_mcp_request_core(&proxy, &manager, &request, Some(&headers)).await?;

        if !is_notification && !response.is_null() {
            let json_str = serde_json::to_string(&response).unwrap_or_default();
            if !session_mgr
                .send_response(&session_id, &json_str)
                .await
            {
                return Err((StatusCode::GONE, "SSE session disconnected".to_string()));
            }
        }

        // Legacy SSE: POST returns 202 Accepted (response goes via SSE stream)
        return Ok(axum::response::IntoResponse::into_response(StatusCode::ACCEPTED));
    }

    info!("📨 Received MCP request for proxy '{}': {}", proxy.name, normalized_path);

    let response = process_mcp_request_core(&proxy, &manager, &request, Some(&headers)).await?;

    // Notifications produce a null response — return 204 No Content
    if response.is_null() {
        return Ok(axum::response::IntoResponse::into_response(StatusCode::NO_CONTENT));
    }

    // ── Streamable HTTP ─────────────────────────────────────────────────────
    // If client sent Accept: text/event-stream, wrap response as SSE
    if crate::mcp::sse_server::client_wants_sse(&headers) {
        let json_str = serde_json::to_string(&response).unwrap_or_default();
        return Ok(crate::mcp::sse_server::build_streamable_http_response(&json_str));
    }

    // ── Synchronous JSON (default) ──────────────────────────────────────────
    Ok(axum::response::IntoResponse::into_response(axum::Json(response)))
}

async fn owned_modern_http_response(
    proxy: &McpProxy,
    manager: &McpServerManager,
    request: &crate::mcp::request_validation::ValidatedModernMessage,
    versions: crate::mcp::request_validation::McpVersionPolicy<'_>,
    request_headers: &HeaderMap,
) -> axum::response::Response {
    use axum::response::IntoResponse;

    if request.method == "subscriptions/listen" {
        return match owned_modern_subscription(proxy, request, versions) {
            Ok(response) => response,
            Err(error) => (*error).into_response(),
        };
    }
    let mut response =
        match process_modern_mcp_request_with_headers(proxy, manager, request, versions, request_headers, None).await {
            Ok(message) => Json(message).into_response(),
            Err(error) => (*error).into_response(),
        };
    response
        .headers_mut()
        .insert("cache-control", axum::http::HeaderValue::from_static("no-store"));
    response
}

pub(crate) fn owned_modern_subscription(
    proxy: &McpProxy,
    request: &crate::mcp::request_validation::ValidatedModernMessage,
    versions: crate::mcp::request_validation::McpVersionPolicy<'_>,
) -> Result<axum::response::Response, Box<crate::mcp::request_validation::McpRequestValidationError>> {
    crate::mcp::modern::require_active_version(request, versions)?;
    let unavailable = || {
        Box::new(crate::mcp::request_validation::McpRequestValidationError {
            status: StatusCode::SERVICE_UNAVAILABLE,
            id: request.id.clone(),
            code: crate::mcp::error_codes::INTERNAL_ERROR,
            message: "MCP catalog subscription is unavailable".to_string(),
            data: None,
        })
    };
    if proxy.status != super::types::McpProxyStatus::Active {
        return Err(unavailable());
    }
    crate::mcp::subscriptions::SubscriptionFilter::from_request(request)?;
    let subscription = crate::mcp::subscriptions::catalog_subscriptions()
        .subscribe(&proxy.id)
        .map_err(|_| unavailable())?;
    crate::mcp::subscriptions::owned_catalog_response(
        request.clone(),
        subscription,
        crate::mcp::modern_sse::SseLimits::from(
            &proxy
                .mcp_http
                .clone()
                .unwrap_or_default(),
        ),
    )
}

/// Handle MCP request with full surface policy support (timeout, retry, circuit breaker, mirroring)
/// This version applies all network policies for feature parity with A2A channels
pub async fn handle_mcp_request_with_policies(
    proxy: &super::types::McpProxy,
    request: serde_json::Value,
    surface: &crate::config::agent_surface::AgentSurface,
    policy_manager: Option<&std::sync::Arc<crate::policies::SurfacePolicyManager>>,
    client: &reqwest::Client,
    channel_name: &str,
    target_auth_header: Option<(String, String)>,
) -> Result<serde_json::Value, String> {
    use rmcp_openapi::Authorization;

    // Check if proxy is active
    if proxy.status != super::types::McpProxyStatus::Active {
        let config_id = surface
            .config_id()
            .unwrap_or("unknown");
        channel_warn!(config_id, "❌ Proxy '{}' is disabled", proxy.name);
        return Err("MCP proxy is disabled".to_string());
    }

    // Create MCP server from proxy config
    let config_id = surface
        .config_id()
        .unwrap_or("unknown");
    channel_info!(config_id, "Creating MCP server for proxy '{}' at {}", proxy.name, proxy.base_url);

    // Parse the OpenAPI spec from YAML to JSON
    let openapi_json: serde_json::Value =
        serde_yaml::from_str(&proxy.openapi_spec).map_err(|e| format!("Failed to parse OpenAPI spec: {}", e))?;

    let base_url = Url::parse(&proxy.base_url).map_err(|e| format!("Invalid base_url: {}", e))?;

    // Build default headers from target auth if configured
    let default_headers = if let Some((header_name, header_value)) = &target_auth_header {
        let mut headers = reqwest::header::HeaderMap::new();
        let name = reqwest::header::HeaderName::from_bytes(header_name.as_bytes())
            .map_err(|e| format!("Invalid target auth header name '{}': {}", header_name, e))?;
        let value = reqwest::header::HeaderValue::from_str(header_value)
            .map_err(|e| format!("Invalid target auth header value: {}", e))?;
        headers.insert(name, value);
        channel_info!(config_id, "Injecting target auth header '{}' into MCP proxy requests", header_name);
        Some(headers)
    } else {
        None
    };

    let mut server = if let Some(headers) = default_headers {
        McpServer::builder()
            .openapi_spec(openapi_json)
            .base_url(base_url)
            .default_headers(headers)
            .build()
    } else {
        McpServer::builder()
            .openapi_spec(openapi_json)
            .base_url(base_url)
            .build()
    };

    server
        .load_openapi_spec()
        .map_err(|e| format!("Failed to load OpenAPI spec: {}", e))?;

    let method = request
        .get("method")
        .and_then(|m| m.as_str())
        .unwrap_or("unknown");
    let request_id = request.get("id").cloned();

    channel_info!(config_id, "🔧 Handling MCP method: {}", method);

    // Get circuit breaker if configured
    let circuit_breaker = if surface
        .circuit_breaker()
        .is_some()
    {
        if let Some(pm) = policy_manager {
            if let Some(config_id) = surface.config_id() {
                pm.get_circuit_breaker(config_id)
                    .await
            } else {
                None
            }
        } else {
            None
        }
    } else {
        None
    };

    match method {
        "initialize" => {
            channel_info!(config_id, "✓ Returning initialize response for '{}'", proxy.name);

            Ok(serde_json::json!({
                "jsonrpc": "2.0",
                "id": request_id,
                "result": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {
                        "tools": {}
                    },
                    "serverInfo": {
                        "name": proxy.name.clone(),
                        "version": "1.0.0"
                    }
                }
            }))
        }
        "tools/list" => {
            let tool_names = server.get_tool_names();
            info!("✓ Found {} tools for proxy '{}'", tool_names.len(), proxy.name);

            let mut tools = Vec::new();
            for tool_name in tool_names {
                if let Some(metadata) = server.get_tool_metadata(&tool_name) {
                    let input_schema = if proxy.flatten_post_params {
                        flatten_input_schema(&metadata.parameters)
                    } else {
                        metadata.parameters.clone()
                    };
                    tools.push(serde_json::json!({
                        "name": metadata.name,
                        "description": metadata.description,
                        "inputSchema": input_schema,
                    }));
                }
            }

            Ok(serde_json::json!({
                "jsonrpc": "2.0",
                "id": request_id,
                "result": {
                    "tools": tools
                }
            }))
        }
        "tools/call" => {
            let params = request
                .get("params")
                .ok_or_else(|| "Missing 'params' in tools/call request".to_string())?;

            let tool_name = params
                .get("name")
                .and_then(|n| n.as_str())
                .ok_or_else(|| "Missing tool 'name' in params".to_string())?;

            let raw_arguments = params
                .get("arguments")
                .cloned()
                .unwrap_or(serde_json::json!({}));

            // Auto-wrap flat arguments into request_body if the tool expects it (only when flattening is enabled)
            let arguments = if proxy.flatten_post_params {
                wrap_request_body_if_needed(&server, tool_name, raw_arguments)
            } else {
                raw_arguments
            };

            channel_info!(config_id, "🔨 Calling tool: {}", tool_name);

            let tool = server
                .get_tool(tool_name)
                .ok_or_else(|| format!("Tool '{}' not found", tool_name))?;

            // Apply timeout if configured
            let timeout_duration = surface
                .timeout()
                .map(|timeout_config| std::time::Duration::from_secs(timeout_config.request_secs));

            // Define the tool call operation with retry logic
            let tool_call_with_retry = || async {
                if let Some(retry_config) = surface.retry() {
                    let mut attempt = 0;
                    let mut _last_error = None;

                    loop {
                        attempt += 1;
                        debug!("Tool call attempt {} of {}", attempt, retry_config.max_attempts + 1);

                        match tool
                            .call(&arguments, Authorization::None, None)
                            .await
                        {
                            Ok(result) => {
                                info!("✓ Tool '{}' executed successfully on attempt {}", tool_name, attempt);
                                return Ok(result);
                            }
                            Err(e) => {
                                if attempt <= retry_config.max_attempts {
                                    warn!("Tool '{}' failed on attempt {}: {}", tool_name, attempt, e);

                                    // Calculate backoff delay
                                    let backoff_ms = std::cmp::min(
                                        (retry_config.initial_backoff_ms as f64
                                            * retry_config
                                                .backoff_multiplier
                                                .powi((attempt - 1) as i32))
                                            as u64,
                                        retry_config.max_backoff_ms,
                                    );

                                    info!("Retrying after {} ms", backoff_ms);
                                    tokio::time::sleep(std::time::Duration::from_millis(backoff_ms)).await;
                                    _last_error = Some(format!("{}", e));
                                    continue;
                                } else {
                                    error!(
                                        "❌ Tool '{}' execution failed after {} attempts: {}",
                                        tool_name, attempt, e
                                    );
                                    return Err(format!("Tool execution failed: {}", e));
                                }
                            }
                        }
                    }
                } else {
                    // No retry configured, call once
                    tool.call(&arguments, Authorization::None, None)
                        .await
                        .map_err(|e| format!("Tool execution failed: {}", e))
                }
            };

            // Apply timeout wrapper if configured
            let tool_call_with_timeout = async {
                if let Some(timeout) = timeout_duration {
                    match tokio::time::timeout(timeout, tool_call_with_retry()).await {
                        Ok(result) => result,
                        Err(_) => {
                            error!("❌ Tool '{}' execution timed out after {:?}", tool_name, timeout);
                            Err(format!("Tool execution timed out after {:?}", timeout))
                        }
                    }
                } else {
                    tool_call_with_retry().await
                }
            };

            // Apply circuit breaker wrapper if configured
            let result = if let Some(cb) = circuit_breaker {
                match cb
                    .call(tool_call_with_timeout)
                    .await
                {
                    Ok(r) => r,
                    Err(crate::policies::CircuitBreakerError::Open { retry_after }) => {
                        error!("Circuit breaker is open for channel '{}', retry after {:?}", channel_name, retry_after);
                        return Err(format!("Circuit breaker open, retry after {:?}", retry_after));
                    }
                    Err(crate::policies::CircuitBreakerError::Inner(e)) => {
                        return Err(format!("Tool execution failed: {}", e));
                    }
                }
            } else {
                tool_call_with_timeout.await?
            };

            // Traffic mirroring for MCP tool calls (if configured)
            if let Some(mirror_config) = surface.mirror() {
                let should_mirror = if mirror_config.percentage >= 100 {
                    true
                } else if mirror_config.percentage == 0 {
                    false
                } else {
                    use rand::Rng;
                    let mut rng = rand::rng();
                    rng.random_range(0..100) < mirror_config.percentage
                };

                if should_mirror {
                    let mirror_endpoint = mirror_config.endpoint.clone();
                    let mirror_timeout = std::time::Duration::from_secs(mirror_config.timeout_secs);
                    let wait_for_response = mirror_config.wait_for_response;
                    let client_clone = client.clone();
                    let request_clone = request.clone();
                    let channel_name_clone = channel_name.to_string();

                    // Send mirror request to mirror endpoint
                    let mirror_task = async move {
                        let mirror_req = client_clone
                            .post(&mirror_endpoint)
                            .json(&request_clone)
                            .timeout(mirror_timeout)
                            .header("Content-Type", "application/json")
                            .header("X-Mirrored-Request", "true");

                        match mirror_req.send().await {
                            Ok(resp) => {
                                info!(
                                    channel = channel_name_clone,
                                    mirror_endpoint = mirror_endpoint,
                                    status = resp.status().as_u16(),
                                    "MCP mirror request completed"
                                );
                            }
                            Err(e) => {
                                warn!(
                                    channel = channel_name_clone,
                                    mirror_endpoint = mirror_endpoint,
                                    error = %e,
                                    "MCP mirror request failed"
                                );
                            }
                        }
                    };

                    if wait_for_response {
                        mirror_task.await;
                    } else {
                        tokio::spawn(mirror_task);
                    }
                }
            }

            Ok(serde_json::json!({
                "jsonrpc": "2.0",
                "id": request_id,
                "result": {
                    "content": result.content,
                    "isError": result.is_error
                }
            }))
        }
        _ => {
            warn!("❌ Unknown MCP method: {}", method);
            Err(format!("Unknown MCP method: {}", method))
        }
    }
}

/// Handle MCP request directly with a proxy object (for channel integration)
/// This is a simplified version that doesn't require Extension dependencies
/// NOTE: This version does NOT apply surface policies - use handle_mcp_request_with_policies for full policy support
#[allow(dead_code)]
pub async fn handle_mcp_request_direct(
    proxy: &super::types::McpProxy,
    request: serde_json::Value,
) -> Result<serde_json::Value, String> {
    use rmcp_openapi::Authorization;

    // Check if proxy is active
    if proxy.status != super::types::McpProxyStatus::Active {
        warn!("❌ Proxy '{}' is disabled", proxy.name);
        return Err("MCP proxy is disabled".to_string());
    }

    // Create MCP server from proxy config
    info!("Creating MCP server for proxy '{}' at {}", proxy.name, proxy.base_url);

    // Parse the OpenAPI spec from YAML to JSON
    let openapi_json: serde_json::Value =
        serde_yaml::from_str(&proxy.openapi_spec).map_err(|e| format!("Failed to parse OpenAPI spec: {}", e))?;

    let base_url = Url::parse(&proxy.base_url).map_err(|e| format!("Invalid base_url: {}", e))?;

    let mut server = McpServer::builder()
        .openapi_spec(openapi_json)
        .base_url(base_url)
        .build();

    server
        .load_openapi_spec()
        .map_err(|e| format!("Failed to load OpenAPI spec: {}", e))?;

    let method = request
        .get("method")
        .and_then(|m| m.as_str())
        .unwrap_or("unknown");
    let request_id = request.get("id").cloned();

    info!("🔧 Handling MCP method: {}", method);

    match method {
        "initialize" => {
            info!("✓ Returning initialize response for '{}'", proxy.name);

            Ok(serde_json::json!({
                "jsonrpc": "2.0",
                "id": request_id,
                "result": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {
                        "tools": {}
                    },
                    "serverInfo": {
                        "name": proxy.name.clone(),
                        "version": "1.0.0"
                    }
                }
            }))
        }
        "tools/list" => {
            let tool_names = server.get_tool_names();
            info!("✓ Found {} tools for proxy '{}'", tool_names.len(), proxy.name);

            let mut tools = Vec::new();
            for tool_name in tool_names {
                if let Some(metadata) = server.get_tool_metadata(&tool_name) {
                    let input_schema = if proxy.flatten_post_params {
                        flatten_input_schema(&metadata.parameters)
                    } else {
                        metadata.parameters.clone()
                    };
                    tools.push(serde_json::json!({
                        "name": metadata.name,
                        "description": metadata.description,
                        "inputSchema": input_schema,
                    }));
                }
            }

            Ok(serde_json::json!({
                "jsonrpc": "2.0",
                "id": request_id,
                "result": {
                    "tools": tools
                }
            }))
        }
        "tools/call" => {
            let params = request
                .get("params")
                .ok_or_else(|| "Missing 'params' in tools/call request".to_string())?;

            let tool_name = params
                .get("name")
                .and_then(|n| n.as_str())
                .ok_or_else(|| "Missing tool 'name' in params".to_string())?;

            let raw_arguments = params
                .get("arguments")
                .cloned()
                .unwrap_or(serde_json::json!({}));

            // Auto-wrap flat arguments into request_body if the tool expects it (only when flattening is enabled)
            let arguments = if proxy.flatten_post_params {
                wrap_request_body_if_needed(&server, tool_name, raw_arguments)
            } else {
                raw_arguments
            };

            info!("🔨 Calling tool: {}", tool_name);

            let tool = server
                .get_tool(tool_name)
                .ok_or_else(|| format!("Tool '{}' not found", tool_name))?;

            match tool
                .call(&arguments, Authorization::None, None)
                .await
            {
                Ok(result) => {
                    info!("✓ Tool '{}' executed successfully", tool_name);

                    Ok(serde_json::json!({
                        "jsonrpc": "2.0",
                        "id": request_id,
                        "result": {
                            "content": result.content,
                            "isError": result.is_error
                        }
                    }))
                }
                Err(e) => {
                    error!("❌ Tool '{}' execution failed: {}", tool_name, e);
                    Err(format!("Tool execution failed: {}", e))
                }
            }
        }
        _ => {
            warn!("❌ Unknown MCP method: {}", method);
            Err(format!("Unknown MCP method: {}", method))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        DiscoverMcpToolsRequest, discovery_secret_allowed, ensure_jsonrpc_success, mcp_proxy_allowed,
        pin_discovery_client, resolve_proxy_id,
    };
    use crate::mcp_proxies::McpProxyStore;
    use axum::http::StatusCode;
    use axum::{Extension, Json, extract::Path};
    use regex::Regex;
    use std::sync::Arc;

    use crate::auth_manager::pat::PatResourceScope;
    use crate::mcp_proxies::types::McpProxy;
    use crate::tenancy::PatTenantContext;

    #[test]
    fn owned_modern_flattening_preserves_mirrors_and_rejects_ambiguous_schemas() {
        use serde_json::json;

        let schema = json!({"type": "object", "properties": {
            "query": {"type": "string"},
            "request_body": {"type": "object", "properties": {
                "region": {"type": "string", "x-mcp-header": "Region"},
                "payload": {"anyOf": [{"type": "string"}, {"type": "integer"}], "com.example/annotation": [true, null]}
            }, "required": ["region"]}
        }, "required": ["request_body"]});
        assert_eq!(super::modern_input_schema(&schema, false).unwrap(), schema);
        let flattened = super::modern_input_schema(&schema, true).unwrap();
        assert_eq!(flattened["properties"]["region"], schema["properties"]["request_body"]["properties"]["region"]);
        assert_eq!(flattened["properties"]["payload"], schema["properties"]["request_body"]["properties"]["payload"]);
        assert_eq!(flattened["required"], json!(["region"]));
        let bindings = crate::mcp::tool_headers::ToolHeaderBindings::compile(&flattened).unwrap();
        let arguments = json!({"query": "search", "region": "east"});
        assert!(
            bindings
                .validate(
                    &arguments,
                    &bindings
                        .encode(&arguments)
                        .unwrap(),
                    None
                )
                .is_ok()
        );
        for field in ["query", "timeout_seconds", "request_body"] {
            let mut collision = schema.clone();
            collision["properties"]["request_body"]["properties"][field] = json!({"type": "string"});
            assert!(super::modern_input_schema(&collision, true).is_err(), "{field}");
        }
        for extra_properties in [true, false] {
            let mut configured = schema.clone();
            configured["properties"]["request_body"]["additionalProperties"] = json!(extra_properties);
            assert_eq!(
                super::modern_input_schema(&configured, true).unwrap()["additionalProperties"],
                json!(extra_properties)
            );
        }
        for (field, value) in [
            ("minProperties", json!(1)),
            ("$defs", json!({"local": {"type": "string"}})),
            ("allOf", json!([{"required": ["region"]}])),
        ] {
            let mut constrained = schema.clone();
            constrained["properties"]["request_body"][field] = value;
            assert!(super::modern_input_schema(&constrained, true).is_err(), "{field}");
            assert_eq!(super::modern_input_schema(&constrained, false).unwrap(), constrained);
        }
        let mut optional = schema;
        optional
            .as_object_mut()
            .unwrap()
            .remove("required");
        assert!(super::modern_input_schema(&optional, true).is_err());
    }

    fn owned_modern_request(method: &str) -> crate::mcp::request_validation::ValidatedModernMessage {
        let body = serde_json::json!({"jsonrpc": "2.0", "id": "owned", "method": method, "params": {"_meta": {
            "io.modelcontextprotocol/protocolVersion": crate::mcp::MCP_MODERN_VERSION,
            "io.modelcontextprotocol/clientCapabilities": {}
        }}});
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            "mcp-protocol-version",
            crate::mcp::MCP_MODERN_VERSION
                .parse()
                .unwrap(),
        );
        headers.insert("mcp-method", method.parse().unwrap());
        let classification = crate::mcp::request_validation::validate_mcp_post(
            &headers,
            &serde_json::to_vec(&body).unwrap(),
            crate::mcp::request_validation::LegacySessionEvidence::Absent,
            crate::mcp::request_validation::McpVersionPolicy::new(
                &[crate::mcp::MCP_MODERN_VERSION],
                &[crate::mcp::MCP_MODERN_VERSION],
            ),
        )
        .unwrap();
        let crate::mcp::request_validation::McpRequestClassification::Modern(request) = classification else {
            panic!("modern fixture expected")
        };
        *request
    }

    #[tokio::test]
    async fn owned_modern_rest_calls_never_follow_redirects() {
        use serde_json::json;

        let destination = crate::component_tests::helpers::MockServer::start_with_response("{}").await;
        let destination_url = destination.url();
        let redirect = axum::Router::new().fallback(axum::routing::get(move || {
            let location = destination_url.clone();
            async move { (StatusCode::FOUND, [("location", location)]) }
        }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap();
        let base_url = format!("http://{}", listener.local_addr().unwrap());
        let mut tasks = tokio::task::JoinSet::new();
        tasks.spawn(async move {
            axum::serve(listener, redirect)
                .await
                .unwrap();
        });
        let proxy = McpProxy::new("Redirecting tool".into(), String::new(), base_url, json!({
            "openapi": "3.0.0", "info": {"title": "Redirect", "version": "1.0"},
            "paths": {"/redirect": {"get": {"operationId": "redirect", "responses": {"200": {"description": "OK"}}}}}
        }).to_string(), "/mcp".into(), "/redirect".into());
        let manager = super::McpServerManager::new();
        manager
            .create_server(&proxy)
            .await
            .unwrap();
        let name = manager
            .get_server(&proxy.id)
            .await
            .unwrap()
            .read()
            .await
            .get_tool_names()
            .pop()
            .unwrap();
        let mut request = owned_modern_request("tools/list");
        request.method = "tools/call".into();
        request
            .params
            .as_mut()
            .unwrap()["name"] = json!(name);
        request
            .params
            .as_mut()
            .unwrap()["arguments"] = json!({});
        let versions = crate::mcp::request_validation::McpVersionPolicy::new(
            &[crate::mcp::MCP_MODERN_VERSION],
            &[crate::mcp::MCP_MODERN_VERSION],
        );
        let result = super::process_modern_mcp_request(&proxy, &manager, &request, versions).await;
        assert_eq!(
            destination
                .request_count
                .load(std::sync::atomic::Ordering::SeqCst),
            0
        );
        let error = result.expect_err("modern REST redirects must fail before a second request");
        assert_eq!(error.status, StatusCode::BAD_GATEWAY);
        assert_eq!(error.code, crate::mcp::error_codes::INTERNAL_ERROR);
        tasks.shutdown().await;
    }

    #[tokio::test]
    async fn owned_modern_multipart_catalog_and_execution_use_the_same_media_type() {
        use serde_json::json;
        use std::collections::HashMap;

        let (observed, mut received) = tokio::sync::mpsc::channel(1);
        let target =
            axum::Router::new().fallback(axum::routing::post(move |mut multipart: axum::extract::Multipart| {
                let observed = observed.clone();
                async move {
                    let mut fields = HashMap::new();
                    while let Some(field) = multipart
                        .next_field()
                        .await
                        .unwrap()
                    {
                        let name = field
                            .name()
                            .unwrap()
                            .to_string();
                        if name == "document" {
                            assert_eq!(field.file_name(), Some("document.txt"));
                            assert_eq!(field.content_type(), Some("text/plain"));
                        }
                        fields.insert(name, field.text().await.unwrap());
                    }
                    observed
                        .send(fields)
                        .await
                        .unwrap();
                    axum::Json(json!({"uploaded": true}))
                }
            }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap();
        let base_url = format!("http://{}", listener.local_addr().unwrap());
        let mut tasks = tokio::task::JoinSet::new();
        tasks.spawn(async move {
            axum::serve(listener, target)
                .await
                .unwrap();
        });
        let proxy = McpProxy::new(
            "Upload".into(),
            String::new(),
            base_url,
            json!({
                "openapi": "3.0.0", "info": {"title": "Upload", "version": "1.0"},
                "paths": {"/upload": {"post": {"operationId": "upload", "requestBody": {"required": true, "content": {
                    "multipart/form-data": {"schema": {"type": "object", "properties": {
                        "document": {"type": "string", "format": "binary"}, "message": {"type": "string"}
                    }, "required": ["document", "message"]}}
                }}, "responses": {"200": {"description": "OK"}}}}}
            })
            .to_string(),
            "/mcp".into(),
            "/upload".into(),
        );
        let manager = super::McpServerManager::new();
        manager
            .create_server(&proxy)
            .await
            .unwrap();
        let versions = crate::mcp::request_validation::McpVersionPolicy::new(
            &[crate::mcp::MCP_MODERN_VERSION],
            &[crate::mcp::MCP_MODERN_VERSION],
        );
        let catalog =
            super::process_modern_mcp_request(&proxy, &manager, &owned_modern_request("tools/list"), versions)
                .await
                .unwrap();
        let tool = &catalog["result"]["tools"][0];
        assert_eq!(tool["inputSchema"]["properties"]["request_body"]["properties"]["document"]["type"], "object");
        let mut request = owned_modern_request("tools/list");
        request.method = "tools/call".into();
        request
            .params
            .as_mut()
            .unwrap()["name"] = tool["name"].clone();
        request
            .params
            .as_mut()
            .unwrap()["arguments"] = json!({"request_body": {
            "message": "hello", "document": {"filename": "document.txt", "content": "data:text/plain;base64,ZmlsZSBjb250ZW50cw=="}
        }});
        let response = super::process_modern_mcp_request(&proxy, &manager, &request, versions)
            .await
            .unwrap();
        assert_eq!(response["result"]["resultType"], "complete");
        assert_eq!(response["result"]["isError"], false);
        let fields = tokio::time::timeout(std::time::Duration::from_secs(2), received.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            fields
                .get("document")
                .map(String::as_str),
            Some("file contents")
        );
        assert_eq!(
            fields
                .get("message")
                .map(String::as_str),
            Some("hello")
        );
        tasks.shutdown().await;
    }

    #[tokio::test]
    async fn owned_modern_calls_enforce_advertised_conditional_schema_constraints() {
        use serde_json::json;

        let target = crate::component_tests::helpers::MockServer::start_with_response("{}").await;
        let input_schema = json!({
            "type": "object", "properties": {"mode": {"type": "string"}, "proof": {"type": "string"}},
            "required": ["mode"], "additionalProperties": false,
            "if": {"properties": {"mode": {"const": "strict"}}},
            "then": {"required": ["proof"]}
        });
        let proxy = McpProxy::new(
            "Conditional tool".into(),
            String::new(),
            target.url(),
            json!({
                "openapi": "3.1.0", "info": {"title": "Conditions", "version": "1.0"}, "paths": {
                    "/check": {"post": {"operationId": "check", "requestBody": {"required": true,
                        "content": {"application/json": {"schema": input_schema}}
                    }, "responses": {"200": {"description": "OK"}}}}
                }
            })
            .to_string(),
            "/mcp".into(),
            "/conditional".into(),
        );
        let manager = super::McpServerManager::new();
        manager
            .create_server(&proxy)
            .await
            .unwrap();
        let versions = crate::mcp::request_validation::McpVersionPolicy::new(
            &[crate::mcp::MCP_MODERN_VERSION],
            &[crate::mcp::MCP_MODERN_VERSION],
        );
        let catalog =
            super::process_modern_mcp_request(&proxy, &manager, &owned_modern_request("tools/list"), versions)
                .await
                .unwrap();
        let tool = &catalog["result"]["tools"][0];
        assert_eq!(tool["inputSchema"]["properties"]["request_body"], input_schema);
        let mut request = owned_modern_request("tools/list");
        request.method = "tools/call".into();
        request
            .params
            .as_mut()
            .unwrap()["name"] = tool["name"].clone();
        request
            .params
            .as_mut()
            .unwrap()["arguments"] = json!({"request_body": {"mode": "strict"}});
        let error = super::process_modern_mcp_request(&proxy, &manager, &request, versions)
            .await
            .expect_err("advertised conditional constraints must apply before dispatch");
        assert_eq!(error.status, StatusCode::BAD_REQUEST);
        assert_eq!(error.code, crate::mcp::error_codes::INVALID_PARAMS);
        assert_eq!(
            target
                .request_count
                .load(std::sync::atomic::Ordering::SeqCst),
            0
        );
        request
            .params
            .as_mut()
            .unwrap()["arguments"]["request_body"]["proof"] = json!("provided");
        let response = super::process_modern_mcp_request(&proxy, &manager, &request, versions)
            .await
            .unwrap();
        assert_eq!(response["result"]["resultType"], "complete");
        assert_eq!(
            target
                .request_count
                .load(std::sync::atomic::Ordering::SeqCst),
            1
        );
    }

    #[tokio::test]
    async fn owned_modern_component_schema_references_remain_enforceable() {
        use serde_json::json;

        let target = crate::component_tests::helpers::MockServer::start_with_response("{}").await;
        let filter_schema = json!({
            "type": "object", "properties": {"pair": {"$ref": "#/components/schemas/Pair"}},
            "required": ["pair"], "additionalProperties": false
        });
        let pair_schema =
            json!({"type": "array", "prefixItems": [{"type": "string"}, {"type": "integer"}], "items": false});
        let proxy = McpProxy::new(
            "Referenced tool".into(),
            String::new(),
            target.url(),
            json!({
                "openapi": "3.1.0", "info": {"title": "References", "version": "1.0"},
                "components": {"schemas": {"Filter": filter_schema, "Pair": pair_schema}},
                "paths": {"/filter": {"post": {"operationId": "filter", "requestBody": {"required": true,
                    "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Filter"}}}
                }, "responses": {"200": {"description": "OK"}}}}}
            })
            .to_string(),
            "/mcp".into(),
            "/referenced".into(),
        );
        let manager = super::McpServerManager::new();
        manager
            .create_server(&proxy)
            .await
            .unwrap();
        let versions = crate::mcp::request_validation::McpVersionPolicy::new(
            &[crate::mcp::MCP_MODERN_VERSION],
            &[crate::mcp::MCP_MODERN_VERSION],
        );
        let catalog =
            super::process_modern_mcp_request(&proxy, &manager, &owned_modern_request("tools/list"), versions)
                .await
                .unwrap();
        let tools = catalog["result"]["tools"]
            .as_array()
            .unwrap();
        assert_eq!(tools.len(), 1, "locally referenced schemas must not disappear from the catalog");
        let schema = &tools[0]["inputSchema"];
        assert_eq!(schema["properties"]["request_body"]["$ref"], "#/components/schemas/Filter");
        assert_eq!(schema["components"]["schemas"]["Filter"], filter_schema);
        assert_eq!(schema["components"]["schemas"]["Pair"], pair_schema);
        let mut request = owned_modern_request("tools/list");
        request.method = "tools/call".into();
        request
            .params
            .as_mut()
            .unwrap()["name"] = tools[0]["name"].clone();
        request
            .params
            .as_mut()
            .unwrap()["arguments"] = json!({"request_body": {"pair": ["value", "wrong"]}});
        let error = super::process_modern_mcp_request(&proxy, &manager, &request, versions)
            .await
            .unwrap_err();
        assert_eq!(error.code, crate::mcp::error_codes::INVALID_PARAMS);
        assert_eq!(
            target
                .request_count
                .load(std::sync::atomic::Ordering::SeqCst),
            0
        );
        request
            .params
            .as_mut()
            .unwrap()["arguments"]["request_body"]["pair"] = json!(["value", 2]);
        let response = super::process_modern_mcp_request(&proxy, &manager, &request, versions)
            .await
            .unwrap();
        assert_eq!(response["result"]["isError"], false);
        assert_eq!(
            target
                .request_count
                .load(std::sync::atomic::Ordering::SeqCst),
            1
        );
    }

    #[tokio::test]
    async fn owned_modern_schema_resources_keep_local_defs_and_reference_scope() {
        use serde_json::json;

        let target = crate::component_tests::helpers::MockServer::start_with_response("{}").await;
        let input_schema = json!({
            "$id": "https://schemas.example/filter", "type": "object",
            "$defs": {"Proof": {"type": "string", "minLength": 5}},
            "properties": {"proof": {"$ref": "#/$defs/Proof"}}, "required": ["proof"]
        });
        let proxy = McpProxy::new(
            "Schema resource".into(),
            String::new(),
            target.url(),
            json!({
                "openapi": "3.1.0", "info": {"title": "Resources", "version": "1.0"},
                "paths": {"/filter": {"post": {"operationId": "filter", "requestBody": {"required": true,
                    "content": {"application/json": {"schema": input_schema}}
                }, "responses": {"200": {"description": "OK"}}}}}
            })
            .to_string(),
            "/mcp".into(),
            "/resource".into(),
        );
        let manager = super::McpServerManager::new();
        let warning = manager
            .create_server(&proxy)
            .await
            .unwrap()
            .expect("legacy catalog warning");
        assert!(warning.contains(crate::mcp::MCP_LEGACY_VERSION), "{warning}");
        assert!(
            manager
                .get_server(&proxy.id)
                .await
                .is_none()
        );
        let versions = crate::mcp::request_validation::McpVersionPolicy::new(
            &[crate::mcp::MCP_MODERN_VERSION],
            &[crate::mcp::MCP_LEGACY_VERSION, crate::mcp::MCP_MODERN_VERSION],
        );
        let discovery =
            super::process_modern_mcp_request(&proxy, &manager, &owned_modern_request("server/discover"), versions)
                .await
                .unwrap();
        assert_eq!(discovery["result"]["supportedVersions"], json!([crate::mcp::MCP_MODERN_VERSION]));
        let before = manager
            .get_catalogs(&proxy.id)
            .await
            .unwrap();
        let mut invalid = proxy.clone();
        invalid.openapi_spec = "not an OpenAPI document".into();
        assert!(
            manager
                .reload_server(&invalid)
                .await
                .is_err()
        );
        let retained = manager
            .get_catalogs(&proxy.id)
            .await
            .unwrap();
        assert!(Arc::ptr_eq(&before.modern, &retained.modern));
        assert!(retained.legacy.is_none());
        let catalog =
            super::process_modern_mcp_request(&proxy, &manager, &owned_modern_request("tools/list"), versions)
                .await
                .unwrap();
        let tools = catalog["result"]["tools"]
            .as_array()
            .unwrap();
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0]["inputSchema"]["properties"]["request_body"], input_schema);
        let mut request = owned_modern_request("tools/list");
        request.method = "tools/call".into();
        request
            .params
            .as_mut()
            .unwrap()["name"] = tools[0]["name"].clone();
        request
            .params
            .as_mut()
            .unwrap()["arguments"] = json!({"request_body": {"proof": "bad"}});
        let error = super::process_modern_mcp_request(&proxy, &manager, &request, versions)
            .await
            .unwrap_err();
        assert_eq!(error.code, crate::mcp::error_codes::INVALID_PARAMS);
        assert_eq!(
            target
                .request_count
                .load(std::sync::atomic::Ordering::SeqCst),
            0
        );
        request
            .params
            .as_mut()
            .unwrap()["arguments"]["request_body"]["proof"] = json!("valid-proof");
        let response = super::process_modern_mcp_request(&proxy, &manager, &request, versions)
            .await
            .unwrap();
        assert_eq!(response["result"]["isError"], false);
        assert_eq!(
            target
                .request_count
                .load(std::sync::atomic::Ordering::SeqCst),
            1
        );
        manager
            .remove_server(&proxy.id)
            .await;
        assert!(
            manager
                .get_catalogs(&proxy.id)
                .await
                .is_none()
        );
        assert!(
            manager
                .get_server(&proxy.id)
                .await
                .is_none()
        );
    }

    #[tokio::test]
    async fn owned_modern_output_schema_preserves_constraints_and_rejects_invalid_results() {
        use serde_json::json;

        let output_schema = json!({"type": "object", "properties": {
            "pair": {"type": "array", "prefixItems": [{"type": "string"}, {"type": "integer"}], "items": false}
        }, "required": ["pair"], "additionalProperties": false, "x-example-display": {"compact": true}});
        for valid in [true, false] {
            let body = if valid {
                json!({"pair": ["value", 2]})
            } else {
                json!({"pair": ["value", "wrong"]})
            };
            let target = crate::component_tests::helpers::MockServer::start_with_response(body.to_string()).await;
            let proxy = McpProxy::new(
                "Output constraints".into(),
                String::new(),
                target.url(),
                json!({
                    "openapi": "3.1.0", "info": {"title": "Output", "version": "1.0"}, "paths": {
                        "/result": {"get": {"operationId": "result", "responses": {"200": {
                            "description": "OK", "content": {"application/json": {"schema": output_schema}}
                        }}}}
                    }
                })
                .to_string(),
                "/mcp".into(),
                "/output".into(),
            );
            let manager = super::McpServerManager::new();
            manager
                .create_server(&proxy)
                .await
                .unwrap();
            let versions = crate::mcp::request_validation::McpVersionPolicy::new(
                &[crate::mcp::MCP_MODERN_VERSION],
                &[crate::mcp::MCP_MODERN_VERSION],
            );
            let catalog =
                super::process_modern_mcp_request(&proxy, &manager, &owned_modern_request("tools/list"), versions)
                    .await
                    .unwrap();
            let tool = &catalog["result"]["tools"][0];
            assert_eq!(tool["outputSchema"]["properties"]["body"]["oneOf"][0], output_schema);
            let mut request = owned_modern_request("tools/list");
            request.method = "tools/call".into();
            request
                .params
                .as_mut()
                .unwrap()["name"] = tool["name"].clone();
            request
                .params
                .as_mut()
                .unwrap()["arguments"] = json!({});
            let result = super::process_modern_mcp_request(&proxy, &manager, &request, versions)
                .await
                .unwrap();
            assert_eq!(result["result"]["resultType"], "complete");
            assert_eq!(result["result"]["isError"], !valid);
            if valid {
                assert_eq!(result["result"]["structuredContent"]["body"], body);
            } else {
                assert!(
                    result["result"]
                        .get("structuredContent")
                        .is_none()
                );
            }
            assert_eq!(
                target
                    .request_count
                    .load(std::sync::atomic::Ordering::SeqCst),
                1
            );
        }
    }

    #[tokio::test]
    async fn owned_modern_dispatch_validates_recognized_mirrors_before_calling_the_target() {
        use serde_json::json;

        let target = crate::component_tests::helpers::MockServer::start_with_response("{}").await;
        let proxy = McpProxy::new("Mirrored tools".into(), String::new(), target.url(), json!({
            "openapi": "3.0.0", "info": {"title": "Mirrors", "version": "1.0"}, "paths": {
                "/echo": {"get": {"operationId": "echo", "parameters": [{"name": "query", "in": "query", "schema": {"type": "string", "x-mcp-header": "Query"}}], "responses": {"200": {"description": "OK"}}}},
                "/broken": {"get": {"operationId": "broken", "parameters": [{"name": "bad", "in": "header", "schema": {"type": "number", "x-mcp-header": "Invalid"}}], "responses": {"200": {"description": "OK"}}}}
            }
        }).to_string(), "/mcp".into(), "/owned".into());
        let manager = super::McpServerManager::new();
        manager
            .create_server(&proxy)
            .await
            .unwrap();
        let cached = manager
            .get_server(&proxy.id)
            .await
            .unwrap();
        let server = cached.read().await;
        let mut valid_name = String::new();
        let mut invalid_name = String::new();
        for name in server.get_tool_names() {
            let tool = server
                .get_tool(&name)
                .unwrap();
            if tool.metadata.path == "/echo" {
                valid_name = name;
            } else {
                invalid_name = name;
            }
        }
        drop(server);
        let versions = crate::mcp::request_validation::McpVersionPolicy::new(
            &[crate::mcp::MCP_MODERN_VERSION],
            &[crate::mcp::MCP_MODERN_VERSION],
        );
        let catalog =
            super::process_modern_mcp_request(&proxy, &manager, &owned_modern_request("tools/list"), versions)
                .await
                .unwrap();
        assert_eq!(
            catalog["result"]["tools"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        assert_eq!(catalog["result"]["tools"][0]["name"], valid_name);
        assert_eq!(catalog["result"]["tools"][0]["inputSchema"]["properties"]["query"]["x-mcp-header"], "Query");
        let mut request = owned_modern_request("tools/list");
        request.method = "tools/call".to_string();
        request
            .params
            .as_mut()
            .unwrap()["name"] = json!(valid_name);
        request
            .params
            .as_mut()
            .unwrap()["arguments"] = json!({"query": " padded "});
        for value in [None, Some("wrong"), Some("=?base64?=")] {
            let mut headers = axum::http::HeaderMap::new();
            if let Some(value) = value {
                headers.insert("mcp-param-query", value.parse().unwrap());
            }
            let error =
                super::process_modern_mcp_request_with_headers(&proxy, &manager, &request, versions, &headers, None)
                    .await
                    .unwrap_err();
            assert_eq!(error.status, StatusCode::BAD_REQUEST);
            assert_eq!(error.code, crate::mcp::error_codes::HEADER_MISMATCH);
            assert_eq!(error.id, Some(json!("owned")));
        }
        request
            .params
            .as_mut()
            .unwrap()["name"] = json!(invalid_name);
        let error = super::process_modern_mcp_request_with_headers(
            &proxy,
            &manager,
            &request,
            versions,
            &axum::http::HeaderMap::new(),
            None,
        )
        .await
        .unwrap_err();
        assert_eq!(error.code, crate::mcp::error_codes::INVALID_PARAMS);
        assert_eq!(
            target
                .request_count
                .load(std::sync::atomic::Ordering::SeqCst),
            0
        );
        request
            .params
            .as_mut()
            .unwrap()["name"] = json!(valid_name);
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            "mcp-param-query",
            crate::mcp::request_validation::encode_mirrored_value(" padded ")
                .parse()
                .unwrap(),
        );
        headers.insert("mcp-param-unknown", "=?base64?=".parse().unwrap());
        headers.insert(
            "authorization",
            "Bearer caller-only"
                .parse()
                .unwrap(),
        );
        let response = super::owned_modern_http_response(&proxy, &manager, &request, versions, &headers).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            target
                .request_count
                .load(std::sync::atomic::Ordering::SeqCst),
            1
        );
        assert!(
            !target
                .last_request_rx
                .borrow()
                .as_ref()
                .unwrap()
                .headers
                .contains_key("authorization")
        );
    }

    #[tokio::test]
    async fn owned_modern_flattened_post_validates_public_mirrors_and_preserves_rest_body() {
        use serde_json::json;

        let target = crate::component_tests::helpers::MockServer::start_with_response("{}").await;
        let mut proxy = McpProxy::new(
            "Flattened calls".into(),
            String::new(),
            target.url(),
            json!({
                "openapi": "3.0.0", "info": {"title": "Flattened calls", "version": "1.0"}, "paths": {
                    "/echo": {"post": {"operationId": "echo", "requestBody": {"required": true, "content": {
                        "application/json": {"schema": {"type": "object", "properties": {
                            "message": {"type": "string", "x-mcp-header": "Message"}
                        }, "required": ["message"]}}
                    }}, "responses": {"200": {"description": "OK"}}}}
                }
            })
            .to_string(),
            "/mcp".into(),
            "/flattened".into(),
        );
        proxy.flatten_post_params = true;
        let manager = super::McpServerManager::new();
        manager
            .create_server(&proxy)
            .await
            .unwrap();
        let versions = crate::mcp::request_validation::McpVersionPolicy::new(
            &[crate::mcp::MCP_MODERN_VERSION],
            &[crate::mcp::MCP_MODERN_VERSION],
        );
        let catalog =
            super::process_modern_mcp_request(&proxy, &manager, &owned_modern_request("tools/list"), versions)
                .await
                .unwrap();
        let tools = catalog["result"]["tools"]
            .as_array()
            .unwrap();
        let cached = manager
            .get_server(&proxy.id)
            .await
            .unwrap();
        let generated = {
            let cached = cached.read().await;
            let name = cached
                .get_tool_names()
                .pop()
                .unwrap();
            cached
                .get_tool_metadata(&name)
                .unwrap()
                .parameters
                .clone()
        };
        assert_eq!(
            tools.len(),
            1,
            "generated schema: {generated}; transformation: {:?}",
            super::modern_input_schema(&generated, true)
        );
        let schema = &tools[0]["inputSchema"];
        assert_eq!(schema["properties"]["message"]["x-mcp-header"], "Message");
        assert!(
            schema["properties"]
                .get("request_body")
                .is_none()
        );
        let mut request = owned_modern_request("tools/list");
        request.method = "tools/call".to_string();
        request
            .params
            .as_mut()
            .unwrap()["name"] = tools[0]["name"].clone();
        request
            .params
            .as_mut()
            .unwrap()["arguments"] = json!({"message": " padded "});
        let mut headers = axum::http::HeaderMap::new();
        let error =
            super::process_modern_mcp_request_with_headers(&proxy, &manager, &request, versions, &headers, None)
                .await
                .unwrap_err();
        assert_eq!(error.code, crate::mcp::error_codes::HEADER_MISMATCH);
        assert_eq!(
            target
                .request_count
                .load(std::sync::atomic::Ordering::SeqCst),
            0
        );
        headers.insert(
            "mcp-param-message",
            crate::mcp::request_validation::encode_mirrored_value(" padded ")
                .parse()
                .unwrap(),
        );
        let response =
            super::process_modern_mcp_request_with_headers(&proxy, &manager, &request, versions, &headers, None)
                .await
                .unwrap();
        assert_eq!(response["result"]["resultType"], "complete");
        let received = target
            .last_request_rx
            .borrow()
            .clone()
            .unwrap();
        assert_eq!(received.method, "POST");
        assert_eq!(serde_json::from_str::<serde_json::Value>(&received.body).unwrap(), json!({"message": " padded "}));
        assert_eq!(
            target
                .request_count
                .load(std::sync::atomic::Ordering::SeqCst),
            1
        );
    }

    #[tokio::test]
    async fn owned_modern_dispatch_surface_uses_target_headers_and_surface_limits() {
        use serde_json::json;

        let target =
            crate::component_tests::helpers::MockServer::start_with_response(json!({"value": "kept"}).to_string())
                .await;
        let proxy = McpProxy::new(
            "Surface tool".into(),
            String::new(),
            target.url(),
            json!({
                "openapi": "3.0.0", "info": {"title": "Tools", "version": "1.0"}, "paths": {
                    "/echo": {"get": {"operationId": "echo", "responses": {"200": {"description": "OK"}}}}
                }
            })
            .to_string(),
            "/mcp".into(),
            "/owned".into(),
        );
        let mut surface: crate::config::agent_surface::AgentSurface = serde_json::from_value(json!({
            "surface_id": "surface-tools", "name": "Surface tools",
            "access_point": {"listen_address": "https://gateway.example", "route": "/tools", "protocol": "mcp"},
            "target": {"endpoint": format!("proxy://{}", proxy.id)}
        }))
        .unwrap();
        let manager = super::McpServerManager::new();
        manager
            .create_server(&proxy)
            .await
            .unwrap();
        let name = manager
            .get_server(&proxy.id)
            .await
            .unwrap()
            .read()
            .await
            .get_tool_names()
            .pop()
            .unwrap();
        let mut request = owned_modern_request("tools/list");
        request.method = "tools/call".to_string();
        request
            .params
            .as_mut()
            .unwrap()["name"] = json!(name);
        request
            .params
            .as_mut()
            .unwrap()["arguments"] = json!({});
        let client = reqwest::Client::new();
        let prepared = || {
            client
                .post(format!("proxy://{}", proxy.id))
                .header("authorization", "Bearer target-test-credential")
                .header("mcp-session-id", "never-forward")
                .header("last-event-id", "never-forward")
                .header("mcp-param-unknown", "never-send-to-rest")
                .body("{}")
                .build()
                .unwrap()
        };
        let versions = crate::mcp::request_validation::McpVersionPolicy::new(
            &[crate::mcp::MCP_MODERN_VERSION],
            &[crate::mcp::MCP_MODERN_VERSION],
        );
        let response = super::handle_modern_surface_request(&proxy, &surface, &request, prepared(), &client, versions)
            .await
            .unwrap();
        assert_eq!(response["id"], "owned");
        assert_eq!(response["result"]["resultType"], "complete");
        let received = target
            .last_request_rx
            .borrow()
            .clone()
            .unwrap();
        assert_eq!(
            received
                .headers
                .get("authorization")
                .map(String::as_str),
            Some("Bearer target-test-credential")
        );
        for name in ["mcp-session-id", "last-event-id", "mcp-param-unknown"] {
            assert!(
                !received
                    .headers
                    .contains_key(name),
                "{name} does not reach the REST backend"
            );
        }
        surface.mcp_http = Some(serde_json::from_value(json!({"max_response_bytes": 1})).unwrap());
        let error = super::handle_modern_surface_request(&proxy, &surface, &request, prepared(), &client, versions)
            .await
            .unwrap_err();
        assert_eq!(error.status, StatusCode::BAD_GATEWAY);
        assert_eq!(error.id, Some(json!("owned")));
    }

    #[tokio::test]
    async fn owned_modern_surface_subscription_uses_surface_limits_without_target_execution() {
        use serde_json::json;
        let proxy = McpProxy::new(
            "Surface subscriptions".into(),
            String::new(),
            "https://example.org".into(),
            String::new(),
            "/mcp".into(),
            "/owned".into(),
        );
        let surface: crate::config::agent_surface::AgentSurface = serde_json::from_value(json!({
            "surface_id": "surface-subscriptions", "name": "Surface subscriptions",
            "mcp_http": {"max_response_bytes": 1},
            "access_point": {"listen_address": "https://gateway.example", "route": "/tools", "protocol": "mcp"},
            "target": {"endpoint": format!("proxy://{}", proxy.id)}
        }))
        .unwrap();
        let mut request = owned_modern_request("subscriptions/listen");
        request
            .params
            .as_mut()
            .unwrap()["notifications"] = json!({});
        let client = reqwest::Client::new();
        let response = super::handle_modern_surface_http_request(
            &proxy,
            &surface,
            &request,
            client
                .post(format!("proxy://{}", proxy.id))
                .build()
                .unwrap(),
            &client,
            crate::mcp::request_validation::McpVersionPolicy::new(
                &[crate::mcp::MCP_MODERN_VERSION],
                &[crate::mcp::MCP_MODERN_VERSION],
            ),
        )
        .await
        .unwrap();
        assert_eq!(response.headers()["content-type"], "text/event-stream");
        assert!(
            axum::body::to_bytes(response.into_body(), 8192)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn owned_modern_subscription_tracks_persisted_catalog_changes_and_removal() {
        use crate::mcp_proxies::McpProxyStore;
        use eventsource_stream::Eventsource;
        use futures::StreamExt;
        use http_body_util::BodyExt;
        use serde_json::json;

        async fn next_message(body: &mut axum::body::Body) -> serde_json::Value {
            let bytes = tokio::time::timeout(std::time::Duration::from_secs(1), body.frame())
                .await
                .unwrap()
                .unwrap()
                .unwrap()
                .into_data()
                .unwrap();
            let events = futures::stream::iter([Ok::<_, std::io::Error>(bytes)]).eventsource();
            futures::pin_mut!(events);
            serde_json::from_str(
                &events
                    .next()
                    .await
                    .unwrap()
                    .unwrap()
                    .data,
            )
            .unwrap()
        }

        let directory = tempfile::tempdir().unwrap();
        let store = crate::mcp_proxies::FileSystemMcpProxyStore::new(directory.path().to_path_buf())
            .await
            .unwrap();
        let mut proxy = McpProxy::new(
            "Subscriptions".into(),
            String::new(),
            "https://example.org".into(),
            json!({"openapi": "3.0.0", "info": {"title": "Tools", "version": "1.0"}, "paths": {}}).to_string(),
            "/mcp".into(),
            "/owned".into(),
        );
        store
            .create(&proxy)
            .await
            .unwrap();
        let manager = super::McpServerManager::new();
        manager
            .create_server(&proxy)
            .await
            .unwrap();
        let mut request = owned_modern_request("subscriptions/listen");
        request
            .params
            .as_mut()
            .unwrap()["notifications"] = json!({"toolsListChanged": true, "resourcesListChanged": true});
        let versions = crate::mcp::request_validation::McpVersionPolicy::new(
            &[crate::mcp::MCP_MODERN_VERSION],
            &[crate::mcp::MCP_MODERN_VERSION],
        );
        let mut body =
            super::owned_modern_http_response(&proxy, &manager, &request, versions, &axum::http::HeaderMap::new())
                .await
                .into_body();
        let ack = next_message(&mut body).await;
        assert_eq!(ack["method"], "notifications/subscriptions/acknowledged");
        assert_eq!(ack["params"]["notifications"], json!({"toolsListChanged": true}));
        proxy.openapi_spec =
            json!({"openapi": "3.0.0", "info": {"title": "Changed", "version": "2.0"}, "paths": {}}).to_string();
        store
            .update(&proxy)
            .await
            .unwrap();
        assert_eq!(next_message(&mut body).await["method"], "notifications/tools/list_changed");
        store
            .delete(&proxy.id)
            .await
            .unwrap();
        let done = next_message(&mut body).await;
        assert_eq!(done["result"]["resultType"], "complete");
        assert_eq!(done["result"]["_meta"]["io.modelcontextprotocol/subscriptionId"], "owned");
        assert!(body.frame().await.is_none());
        proxy.status = crate::mcp_proxies::types::McpProxyStatus::Disabled;
        let error = super::owned_modern_subscription(&proxy, &request, versions).unwrap_err();
        assert_eq!(error.status, StatusCode::SERVICE_UNAVAILABLE);
        let error =
            super::owned_modern_subscription(&proxy, &request, crate::mcp::request_validation::LEGACY_ONLY_POLICY)
                .unwrap_err();
        assert_eq!(error.code, crate::mcp::error_codes::UNSUPPORTED_PROTOCOL_VERSION);
    }

    #[tokio::test]
    async fn owned_modern_dispatch_http_preserves_error_ids_and_never_creates_sessions() {
        use serde_json::json;

        let proxy = McpProxy::new(
            "Owned HTTP".into(),
            String::new(),
            "https://example.com".into(),
            json!({"openapi": "3.0.0", "info": {"title": "Tools", "version": "1.0"}, "paths": {}}).to_string(),
            "/mcp".into(),
            "/owned".into(),
        );
        let manager = super::McpServerManager::new();
        manager
            .create_server(&proxy)
            .await
            .unwrap();
        let versions = crate::mcp::request_validation::McpVersionPolicy::new(
            &[crate::mcp::MCP_MODERN_VERSION],
            &[crate::mcp::MCP_MODERN_VERSION],
        );
        for (method, expected_status, expected_code) in [
            ("server/discover", StatusCode::OK, None),
            ("tools/list", StatusCode::OK, None),
            ("unknown/method", StatusCode::NOT_FOUND, Some(-32601)),
        ] {
            let response = super::owned_modern_http_response(
                &proxy,
                &manager,
                &owned_modern_request(method),
                versions,
                &axum::http::HeaderMap::new(),
            )
            .await;
            assert_eq!(response.status(), expected_status);
            assert_eq!(response.headers()["cache-control"], "no-store");
            assert!(
                !response
                    .headers()
                    .contains_key("mcp-session-id")
            );
            let message: serde_json::Value = serde_json::from_slice(
                &axum::body::to_bytes(response.into_body(), 8192)
                    .await
                    .unwrap(),
            )
            .unwrap();
            assert_eq!(message["id"], "owned");
            if let Some(code) = expected_code {
                assert_eq!(message["error"]["code"], code);
                assert!(
                    message
                        .get("result")
                        .is_none()
                );
            } else {
                assert_eq!(message["result"]["resultType"], "complete");
            }
        }
        let mut notification = owned_modern_request("notifications/initialized");
        notification.id = None;
        notification.kind = crate::mcp::request_validation::McpMessageKind::Notification;
        let response =
            super::owned_modern_http_response(&proxy, &manager, &notification, versions, &axum::http::HeaderMap::new())
                .await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let message: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), 8192)
                .await
                .unwrap(),
        )
        .unwrap();
        assert!(message.get("id").is_none());
        assert_eq!(message["error"]["code"], -32601);
    }

    #[tokio::test]
    async fn owned_modern_dispatch_validates_calls_and_releases_the_catalog_lock() {
        use serde_json::json;

        let (target, release) =
            crate::component_tests::helpers::MockServer::start_paused(json!({"value": [true, null]}).to_string()).await;
        let spec = json!({"openapi": "3.0.0", "info": {"title": "Tools", "version": "1.0"}, "paths": {
            "/echo": {"get": {"operationId": "echo", "parameters": [{"name": "query", "in": "query", "required": true, "schema": {"type": "string"}}],
                "responses": {"200": {"description": "OK", "content": {"application/json": {"schema": {"type": "object"}}}}}}}
        }});
        let proxy = McpProxy::new(
            "Owned calls".into(),
            String::new(),
            target.url(),
            spec.to_string(),
            "/mcp".into(),
            "/owned".into(),
        );
        let manager = Arc::new(super::McpServerManager::new());
        manager
            .create_server(&proxy)
            .await
            .unwrap();
        let cached = manager
            .get_server(&proxy.id)
            .await
            .unwrap();
        let name = cached
            .read()
            .await
            .get_tool_names()
            .pop()
            .unwrap();
        let versions = crate::mcp::request_validation::McpVersionPolicy::new(
            &[crate::mcp::MCP_MODERN_VERSION],
            &[crate::mcp::MCP_MODERN_VERSION],
        );
        for (tool, arguments) in
            [(&name, json!([])), (&name, json!({})), (&"missing".to_string(), json!({"query": "valid"}))]
        {
            let mut request = owned_modern_request("tools/list");
            request.method = "tools/call".to_string();
            request
                .params
                .as_mut()
                .unwrap()["name"] = json!(tool);
            request
                .params
                .as_mut()
                .unwrap()["arguments"] = arguments;
            let error = super::process_modern_mcp_request(&proxy, &manager, &request, versions)
                .await
                .unwrap_err();
            assert_eq!(error.code, crate::mcp::error_codes::INVALID_PARAMS);
            assert_eq!(error.status, StatusCode::BAD_REQUEST);
        }
        assert_eq!(
            target
                .request_count
                .load(std::sync::atomic::Ordering::SeqCst),
            0
        );
        let mut request = owned_modern_request("tools/list");
        request.method = "tools/call".to_string();
        request
            .params
            .as_mut()
            .unwrap()["name"] = json!(name);
        request
            .params
            .as_mut()
            .unwrap()["arguments"] = json!({"query": "valid"});
        let mut received = target.last_request_rx.clone();
        received.borrow_and_update();
        let pending = tokio::spawn({
            let manager = manager.clone();
            async move {
                super::process_modern_mcp_request(
                    &proxy,
                    &manager,
                    &request,
                    crate::mcp::request_validation::McpVersionPolicy::new(
                        &[crate::mcp::MCP_MODERN_VERSION],
                        &[crate::mcp::MCP_MODERN_VERSION],
                    ),
                )
                .await
            }
        });
        tokio::time::timeout(std::time::Duration::from_secs(2), received.changed())
            .await
            .unwrap()
            .unwrap();
        let write = tokio::time::timeout(std::time::Duration::from_secs(1), cached.write())
            .await
            .unwrap();
        drop(write);
        assert!(!pending.is_finished());
        release.notify_one();
        let response = pending
            .await
            .unwrap()
            .unwrap();
        assert_eq!(response["id"], "owned");
        assert_eq!(response["result"]["resultType"], "complete");
        assert_eq!(response["result"]["isError"], false);
        assert_eq!(response["result"]["structuredContent"]["body"], json!({"value": [true, null]}));
        assert!(
            !response["result"]["content"]
                .as_array()
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            target
                .request_count
                .load(std::sync::atomic::Ordering::SeqCst),
            1
        );
    }

    #[tokio::test]
    async fn owned_modern_dispatch_has_truthful_discovery_and_preserves_tool_metadata() {
        let spec = serde_json::json!({"openapi": "3.0.0", "info": {"title": "Tools", "version": "1.0"}, "paths": {
            "/zulu": {"get": {"operationId": "zulu", "summary": "Zulu tool", "responses": {"200": {"description": "OK", "content": {"application/json": {"schema": {"type": "object", "properties": {"value": {"type": "string"}}}}}}}}},
            "/alpha": {"get": {"operationId": "alpha", "summary": "Alpha tool", "responses": {"200": {"description": "OK"}}}}
        }});
        let proxy = McpProxy::new(
            "Owned tools".into(),
            String::new(),
            "https://example.com".into(),
            spec.to_string(),
            "/mcp".into(),
            "/owned".into(),
        );
        let manager = super::McpServerManager::new();
        manager
            .create_server(&proxy)
            .await
            .unwrap();
        let versions = crate::mcp::request_validation::McpVersionPolicy::new(
            &[crate::mcp::MCP_MODERN_VERSION],
            &[crate::mcp::MCP_LEGACY_VERSION, crate::mcp::MCP_MODERN_VERSION],
        );
        let discovery =
            super::process_modern_mcp_request(&proxy, &manager, &owned_modern_request("server/discover"), versions)
                .await
                .unwrap();
        assert_eq!(discovery["result"]["capabilities"], serde_json::json!({"tools": {"listChanged": true}}));
        assert_eq!(
            discovery["result"]["supportedVersions"],
            serde_json::json!([crate::mcp::MCP_LEGACY_VERSION, crate::mcp::MCP_MODERN_VERSION])
        );
        let list = super::process_modern_mcp_request(&proxy, &manager, &owned_modern_request("tools/list"), versions)
            .await
            .unwrap();
        assert_eq!(list["id"], "owned");
        assert_eq!(list["result"]["resultType"], "complete");
        assert_eq!(list["result"]["cacheScope"], "private");
        assert_eq!(list["result"]["ttlMs"], 0);
        let tools = list["result"]["tools"]
            .as_array()
            .unwrap();
        assert_eq!(tools.len(), 2);
        assert!(
            tools[0]["name"]
                .as_str()
                .unwrap()
                < tools[1]["name"]
                    .as_str()
                    .unwrap()
        );
        let cached = manager
            .get_server(&proxy.id)
            .await
            .unwrap();
        let cached = cached.read().await;
        for tool in tools {
            let metadata = cached
                .get_tool_metadata(tool["name"].as_str().unwrap())
                .unwrap();
            assert_eq!(tool["inputSchema"], metadata.parameters);
            let mut expected_output = metadata.output_schema.clone();
            if let Some(output) = expected_output.as_mut() {
                output["properties"]["body"]["oneOf"][0] = spec["paths"][&metadata.path][metadata
                    .method
                    .to_ascii_lowercase()]["responses"]["200"]["content"]["application/json"]["schema"]
                    .clone();
                assert_eq!(
                    metadata
                        .output_schema
                        .as_ref()
                        .unwrap()["properties"]["body"]["oneOf"][0]["additionalProperties"],
                    true
                );
            }
            assert_eq!(tool.get("outputSchema"), expected_output.as_ref());
            assert_eq!(
                tool.get("title")
                    .and_then(serde_json::Value::as_str),
                metadata.title.as_deref()
            );
            assert_eq!(
                tool["annotations"],
                serde_json::json!(
                    metadata
                        .generate_annotations()
                        .unwrap()
                )
            );
            assert!(tool.get("method").is_none());
            assert!(tool.get("security").is_none());
        }
        for method in ["initialize", "tasks/get", "notifications/initialized"] {
            let error = super::process_modern_mcp_request(&proxy, &manager, &owned_modern_request(method), versions)
                .await
                .unwrap_err();
            assert_eq!(error.status, StatusCode::NOT_FOUND);
            assert_eq!(error.code, crate::mcp::error_codes::METHOD_NOT_FOUND);
            assert_eq!(error.id, Some(serde_json::json!("owned")));
        }
        let error = super::process_modern_mcp_request(
            &proxy,
            &manager,
            &owned_modern_request("tools/list"),
            crate::mcp::request_validation::LEGACY_ONLY_POLICY,
        )
        .await
        .unwrap_err();
        assert_eq!(error.code, crate::mcp::error_codes::UNSUPPORTED_PROTOCOL_VERSION);
    }

    async fn standalone_mcp_router() -> (axum::Router, super::SseSessionManager, tempfile::TempDir) {
        use crate::mcp_proxies::McpProxyStore;

        let directory = tempfile::tempdir().unwrap();
        let store = Arc::new(
            crate::mcp_proxies::FileSystemMcpProxyStore::new(directory.path().to_path_buf())
                .await
                .unwrap(),
        );
        let manager = Arc::new(super::McpServerManager::new());
        let sessions = super::SseSessionManager::new(None);
        let mut proxy = McpProxy::new(
            "Owned MCP".into(),
            String::new(),
            "https://example.com".into(),
            "openapi: 3.0.0\ninfo:\n  title: Test\n  version: 1.0.0\npaths: {}\n".into(),
            "/mcp".into(),
            "/owned".into(),
        );
        proxy.mcp_http = Some(
            serde_json::from_value(
                serde_json::json!({"allowed_origins": ["https://console.example"], "max_request_bytes": 1024}),
            )
            .unwrap(),
        );
        manager
            .create_server(&proxy)
            .await
            .unwrap();
        store
            .create(&proxy)
            .await
            .unwrap();
        let network: crate::config::NetworkConfig = serde_json::from_value(serde_json::json!({
            "did": {"domain": "gateway.example"}, "webauthn": {"rp_id": "test", "external_origin": "https://gateway.example"},
            "integration": {"types": [], "categories": []}, "listeners": [], "routes": {}
        })).unwrap();
        let router = axum::Router::new()
            .route(
                "/mcp/{*path}",
                axum::routing::post(super::handle_mcp_post::<crate::mcp_proxies::FileSystemMcpProxyStore>)
                    .get(super::handle_mcp_get::<crate::mcp_proxies::FileSystemMcpProxyStore>)
                    .delete(super::handle_mcp_get::<crate::mcp_proxies::FileSystemMcpProxyStore>),
            )
            .layer(axum::Extension(store))
            .layer(axum::Extension(manager))
            .layer(axum::Extension(sessions.clone()))
            .layer(axum::Extension(Arc::new(network)));
        (router, sessions, directory)
    }

    #[tokio::test]
    async fn standalone_mcp_http_non_post_ownership_preserves_legacy_sse() {
        use tower::ServiceExt;

        let (router, _sessions, _directory) = standalone_mcp_router().await;
        for method in [axum::http::Method::GET, axum::http::Method::DELETE] {
            let response = router
                .clone()
                .oneshot(
                    axum::http::Request::builder()
                        .method(method.clone())
                        .uri("/mcp/owned")
                        .header("mcp-protocol-version", "2026-07-28")
                        .header("mcp-session-id", "legacy-session")
                        .body(axum::body::Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
            assert_eq!(response.headers()["allow"], "POST");
        }
        let sse = router
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .uri("/mcp/owned/sse")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(sse.status(), StatusCode::OK);
        assert_eq!(sse.headers()["content-type"], "text/event-stream");
        drop(sse);
        let invalid_origin = router
            .oneshot(
                axum::http::Request::builder()
                    .uri("/mcp/owned/sse")
                    .header("origin", "https://untrusted.example")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(invalid_origin.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn standalone_mcp_http_validates_raw_posts_before_legacy_sessions() {
        use tower::ServiceExt;

        let (router, sessions, _directory) = standalone_mcp_router().await;
        let (session_id, _stream) = sessions
            .create_session()
            .await;
        let body = serde_json::json!({"jsonrpc": "2.0", "id": "standalone", "method": "server/discover", "params": {"_meta": {
            "io.modelcontextprotocol/protocolVersion": "2025-11-25", "io.modelcontextprotocol/clientCapabilities": {}
        }}}).to_string();
        for (path, body, expected_code) in [
            ("/mcp/owned".to_string(), body.clone(), -32022),
            (format!("/mcp/owned/mcp/messages?session_id={session_id}"), body.clone(), -32022),
            ("/mcp/owned/mcp/messages?session_id=missing".to_string(), body, -32022),
            ("/mcp/owned".to_string(), "{".to_string(), -32700),
            ("/mcp/owned".to_string(), String::new(), -32700),
        ] {
            let response = router
                .clone()
                .oneshot(
                    axum::http::Request::builder()
                        .method("POST")
                        .uri(path)
                        .header("content-type", "application/json")
                        .header("accept", "application/json, text/event-stream")
                        .header("mcp-protocol-version", "2025-11-25")
                        .header("mcp-method", "server/discover")
                        .header("mcp-session-id", &session_id)
                        .body(axum::body::Body::from(body))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
            let body: serde_json::Value = serde_json::from_slice(
                &axum::body::to_bytes(response.into_body(), 8192)
                    .await
                    .unwrap(),
            )
            .unwrap();
            assert_eq!(body["error"]["code"], expected_code);
            if expected_code == -32022 {
                assert_eq!(body["id"], "standalone");
                assert_eq!(
                    body["error"]["data"]["supported"],
                    serde_json::json!(
                        crate::mcp::request_validation::runtime_policy_for(
                            crate::mcp::request_validation::McpPathKind::OwnedProxy
                        )
                        .supported_versions()
                    )
                );
            } else {
                assert!(body.get("id").is_none());
            }
        }
    }

    #[tokio::test]
    async fn standalone_mcp_http_rejects_every_admission_negative_case() {
        use crate::mcp::admission_cases::{admission_cases, assert_rejected};
        use tower::ServiceExt;

        let (router, _sessions, _directory) = standalone_mcp_router().await;
        for case in admission_cases() {
            let mut request = axum::http::Request::builder()
                .method("POST")
                .uri("/mcp/owned");
            for (name, value) in &case.headers {
                request = request.header(*name, value.clone());
            }
            let response = router
                .clone()
                .oneshot(
                    request
                        .body(axum::body::Body::from(case.body.clone()))
                        .unwrap(),
                )
                .await
                .unwrap();
            let status = response.status();
            let body: serde_json::Value = serde_json::from_slice(
                &axum::body::to_bytes(response.into_body(), 8192)
                    .await
                    .unwrap(),
            )
            .unwrap();
            assert_rejected(&case, status, &body, "standalone MCP Proxy");
        }
    }

    #[tokio::test]
    async fn standalone_mcp_http_keeps_legacy_initialization_notifications_and_sse() {
        use tower::ServiceExt;

        let (router, sessions, _directory) = standalone_mcp_router().await;
        let (session_id, _stream) = sessions
            .create_session()
            .await;
        for (path, method, expected_status) in [
            ("/mcp/owned".to_string(), "initialize", StatusCode::OK),
            ("/mcp/owned".to_string(), "notifications/initialized", StatusCode::NO_CONTENT),
            (format!("/mcp/owned/mcp/messages?session_id={session_id}"), "initialize", StatusCode::ACCEPTED),
        ] {
            let mut body = serde_json::json!({"jsonrpc": "2.0", "method": method});
            if method == "initialize" {
                body["id"] = serde_json::json!(1);
            }
            let response = router
                .clone()
                .oneshot(
                    axum::http::Request::builder()
                        .method("POST")
                        .uri(path)
                        .header("content-type", "application/json")
                        .body(axum::body::Body::from(body.to_string()))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), expected_status);
            let body = axum::body::to_bytes(response.into_body(), 8192)
                .await
                .unwrap();
            if expected_status == StatusCode::OK {
                let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
                assert_eq!(body["result"]["protocolVersion"], "2024-11-05");
                assert!(
                    body["result"]
                        .get("resultType")
                        .is_none()
                );
            } else {
                assert!(body.is_empty());
            }
        }
        let response = router
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri("/mcp/owned")
                    .header("content-type", "application/json")
                    .header("origin", "https://untrusted.example")
                    .body(axum::body::Body::from(
                        serde_json::json!({"jsonrpc": "2.0", "id": 1, "method": "initialize"}).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let oversized = router
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri("/mcp/owned")
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(" ".repeat(1025)))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(oversized.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[test]
    fn resolve_proxy_id_prefers_explicit_proxy_id() {
        let request = DiscoverMcpToolsRequest {
            target_endpoint: Some("proxy://from-target".to_string()),
            mcp_proxy_id: Some("from-field".to_string()),
            target_auth: None,
        };

        assert_eq!(resolve_proxy_id(&request), Some("from-field".to_string()));
    }

    #[test]
    fn resolve_proxy_id_extracts_proxy_scheme_target() {
        let request = DiscoverMcpToolsRequest {
            target_endpoint: Some("proxy://weather-tools".to_string()),
            mcp_proxy_id: None,
            target_auth: None,
        };

        assert_eq!(resolve_proxy_id(&request), Some("weather-tools".to_string()));
    }

    #[test]
    fn ensure_jsonrpc_success_accepts_result_payload() {
        let response = r#"{"jsonrpc":"2.0","id":"tools-list","result":{"tools":[{"name":"search"}]}}"#;

        let parsed = ensure_jsonrpc_success(response).expect("result payload should parse");
        assert_eq!(parsed["result"]["tools"][0]["name"], "search");
    }

    #[test]
    fn ensure_jsonrpc_success_rejects_error_payload() {
        let response = r#"{"jsonrpc":"2.0","id":"tools-list","error":{"code":-32000,"message":"upstream failed"}}"#;

        let error = ensure_jsonrpc_success(response).expect_err("error payload should fail");
        assert_eq!(error.0, StatusCode::BAD_GATEWAY);
        assert!(
            error
                .1
                .contains("upstream failed")
        );
    }

    #[test]
    fn discovery_target_validation_rejects_cloud_metadata_and_loopback() {
        assert!(crate::url_validation::validate_resolved_url("http://169.254.169.254/latest/meta-data").is_err());
        assert!(crate::url_validation::validate_resolved_url("http://127.0.0.1:8080/mcp").is_err());
    }

    #[tokio::test]
    async fn pin_discovery_client_rejects_metadata_and_loopback_without_leaking_ip() {
        for raw in ["http://169.254.169.254/latest/meta-data", "http://127.0.0.1:8080/mcp"] {
            let err = pin_discovery_client(raw)
                .await
                .expect_err("strict pin must reject internal/metadata target");
            assert_eq!(err.0, StatusCode::BAD_REQUEST);
            assert_eq!(err.1, "Invalid MCP target endpoint");
            // The resolved IP must stay log-only, never surfaced to the caller.
            assert!(
                !err.1
                    .contains("169.254.169.254")
            );
            assert!(!err.1.contains("127.0.0.1"));
        }
    }

    #[test]
    fn discovery_requires_proxy_and_secret_tenant_scope_access() {
        let context = PatTenantContext {
            token_id: "token-a".to_string(),
            tenant_id: "tenant-a".to_string(),
        };
        let scope = PatResourceScope(Arc::new(
            Regex::new(r"\ATENANT:tenant-a:(?:mcp-proxies:proxy-a|secrets:secret-a)\z").unwrap(),
        ));
        let mut proxy = McpProxy::new(
            "Proxy".to_string(),
            String::new(),
            "https://example.com".to_string(),
            "openapi: 3.0.0".to_string(),
            "/mcp".to_string(),
            "/proxy".to_string(),
        );
        proxy.id = "proxy-a".to_string();
        proxy.tenant_id = Some("tenant-a".to_string());

        assert!(mcp_proxy_allowed(&proxy, Some(&context), Some(&scope)));
        assert!(discovery_secret_allowed(Some("tenant-a"), "secret-a", Some(&context), Some(&scope)));
        assert!(!discovery_secret_allowed(Some("tenant-b"), "secret-a", Some(&context), Some(&scope)));
        assert!(!discovery_secret_allowed(Some("tenant-a"), "secret-b", Some(&context), Some(&scope)));

        proxy.tenant_id = Some("tenant-b".to_string());
        assert!(!mcp_proxy_allowed(&proxy, Some(&context), Some(&scope)));
    }

    struct ListStore(Vec<McpProxy>);

    #[async_trait::async_trait]
    impl crate::mcp_proxies::McpProxyStore for ListStore {
        async fn create(
            &self,
            _proxy: &McpProxy,
        ) -> anyhow::Result<()> {
            Ok(())
        }
        async fn get(
            &self,
            id: &str,
        ) -> anyhow::Result<Option<McpProxy>> {
            Ok(self
                .0
                .iter()
                .find(|p| p.id == id)
                .cloned())
        }
        async fn list_all(&self) -> anyhow::Result<Vec<McpProxy>> {
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
            _proxy: &McpProxy,
        ) -> anyhow::Result<()> {
            Ok(())
        }
    }

    fn proxy_at(
        endpoint_path: &str,
        direct_access: bool,
    ) -> McpProxy {
        let mut proxy = McpProxy::new(
            endpoint_path.to_string(),
            String::new(),
            "https://api.example.com".to_string(),
            "openapi: 3.0.0".to_string(),
            "/mcp".to_string(),
            endpoint_path.to_string(),
        );
        proxy.direct_access = direct_access;
        proxy
    }

    #[test]
    fn endpoint_path_matches_only_on_a_segment_boundary() {
        assert!(super::endpoint_path_matches("/foo", "/foo"));
        assert!(super::endpoint_path_matches("/foo/sse", "/foo"));
        assert!(super::endpoint_path_matches("/foo/mcp/messages", "/foo"));
        assert!(super::endpoint_path_matches("/foo/bar", "/foo/"));
        assert!(!super::endpoint_path_matches("/foobar", "/foo"));
        assert!(!super::endpoint_path_matches("/foobar/sse", "/foo"));
        assert!(!super::endpoint_path_matches("/fo", "/foo"));
    }

    #[tokio::test]
    async fn direct_route_serves_a_proxy_with_direct_access() {
        let store = ListStore(vec![proxy_at("/weather", true)]);
        let (proxy, suffix) = super::find_proxy_for_path(&store, "/weather/sse")
            .await
            .expect("served");
        assert_eq!(proxy.endpoint_path, "/weather");
        assert_eq!(suffix, "/sse");
    }

    #[tokio::test]
    async fn direct_route_hides_a_surface_only_proxy_as_not_found() {
        let store = ListStore(vec![proxy_at("/weather", false)]);
        let err = super::find_proxy_for_path(&store, "/weather")
            .await
            .expect_err("a surface-only proxy is not served directly");
        assert_eq!(err.0, StatusCode::NOT_FOUND);
        assert!(!err.1.contains("direct"), "the refusal must not reveal the proxy exists: {}", err.1);
    }

    #[tokio::test]
    async fn direct_route_does_not_let_one_proxy_capture_a_longer_path() {
        let store = ListStore(vec![proxy_at("/foo", true), proxy_at("/foobar", true)]);
        let (proxy, _) = super::find_proxy_for_path(&store, "/foobar/sse")
            .await
            .expect("served");
        assert_eq!(proxy.endpoint_path, "/foobar");
        let store = ListStore(vec![proxy_at("/foo", true)]);
        assert!(
            super::find_proxy_for_path(&store, "/foobar")
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn direct_route_prefers_the_longest_matching_endpoint() {
        let store = ListStore(vec![proxy_at("/api", true), proxy_at("/api/weather", true)]);
        let (proxy, suffix) = super::find_proxy_for_path(&store, "/api/weather/sse")
            .await
            .expect("served");
        assert_eq!(proxy.endpoint_path, "/api/weather");
        assert_eq!(suffix, "/sse");
    }

    async fn direct_get(
        proxies: Vec<McpProxy>,
        path: &str,
    ) -> Result<axum::response::Response, (StatusCode, String)> {
        let network: crate::config::NetworkConfig = serde_json::from_value(serde_json::json!({
            "did": {"domain": "gateway.example"}, "webauthn": {"rp_id": "test", "external_origin": "https://gateway.example"},
            "integration": {"types": [], "categories": []}, "listeners": [], "routes": {}
        }))
        .unwrap();
        super::handle_mcp_get(
            Extension(Arc::new(ListStore(proxies))),
            Extension(crate::mcp::sse_server::SseSessionManager::new(None)),
            Extension(Arc::new(network)),
            None,
            axum::http::Method::GET,
            axum::http::HeaderMap::new(),
            Path(path.to_string()),
        )
        .await
    }

    async fn configured(response: axum::response::Response) -> serde_json::Value {
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body");
        serde_json::from_slice::<serde_json::Value>(&bytes).expect("json")["configured"].clone()
    }

    #[tokio::test]
    async fn direct_get_opens_sse_and_reports_a_proxy_with_direct_access() {
        let sse = direct_get(vec![proxy_at("/weather", true)], "/weather/sse")
            .await
            .expect("an SSE session opens");
        assert_eq!(sse.status(), StatusCode::OK);
        let info = direct_get(vec![proxy_at("/weather", true)], "/weather")
            .await
            .expect("info");
        assert_eq!(configured(info).await, serde_json::json!(true));
    }

    #[tokio::test]
    async fn direct_get_neither_opens_sse_nor_reveals_a_surface_only_proxy() {
        let err = direct_get(vec![proxy_at("/weather", false)], "/weather/sse")
            .await
            .expect_err("no SSE session for a surface-only proxy");
        assert_eq!(err.0, StatusCode::NOT_FOUND);
        let info = direct_get(vec![proxy_at("/weather", false)], "/weather")
            .await
            .expect("info");
        assert_eq!(configured(info).await, serde_json::json!(false));
    }

    #[derive(Default)]
    struct MemStore(std::sync::Mutex<Vec<McpProxy>>);

    #[async_trait::async_trait]
    impl crate::mcp_proxies::McpProxyStore for MemStore {
        async fn create(
            &self,
            proxy: &McpProxy,
        ) -> anyhow::Result<()> {
            let mut all = self.0.lock().unwrap();
            all.retain(|p| p.id != proxy.id);
            all.push(proxy.clone());
            Ok(())
        }
        async fn get(
            &self,
            id: &str,
        ) -> anyhow::Result<Option<McpProxy>> {
            Ok(self
                .0
                .lock()
                .unwrap()
                .iter()
                .find(|p| p.id == id)
                .cloned())
        }
        async fn list_all(&self) -> anyhow::Result<Vec<McpProxy>> {
            Ok(self.0.lock().unwrap().clone())
        }
        async fn delete(
            &self,
            id: &str,
        ) -> anyhow::Result<()> {
            self.0
                .lock()
                .unwrap()
                .retain(|p| p.id != id);
            Ok(())
        }
        async fn update(
            &self,
            proxy: &McpProxy,
        ) -> anyhow::Result<()> {
            self.create(proxy).await
        }
    }

    const SPEC: &str = "openapi: 3.0.0\ninfo:\n  title: t\n  version: '1'\npaths:\n  /pets:\n    get:\n      operationId: listPets\n      responses:\n        '200':\n          description: ok\n";

    fn owned(
        id: &str,
        tenant: Option<&str>,
    ) -> McpProxy {
        let mut proxy = proxy_at(&format!("/{id}"), false);
        proxy.id = id.to_string();
        proxy.tenant_id = tenant.map(str::to_string);
        proxy
    }

    fn no_resource_owners() -> Arc<crate::sts::resource_owners::ApplianceResourceOwners> {
        Arc::new(crate::sts::resource_owners::ApplianceResourceOwners::new(
            None,
            None,
            crate::sts::resource_owners::tests::network(),
        ))
    }

    fn store_with(proxies: Vec<McpProxy>) -> Arc<MemStore> {
        Arc::new(MemStore(std::sync::Mutex::new(proxies)))
    }

    fn tenant(id: &str) -> Option<Extension<PatTenantContext>> {
        Some(Extension(PatTenantContext {
            token_id: "agat_test".into(),
            tenant_id: id.into(),
        }))
    }

    fn scope(pattern: &str) -> Option<Extension<PatResourceScope>> {
        Some(Extension(PatResourceScope(Arc::new(Regex::new(pattern).unwrap()))))
    }

    fn open_scope() -> Option<Extension<PatResourceScope>> {
        scope(r"\ATENANT:tenant-a:mcp-proxies:.*\z")
    }

    fn rename(name: &str) -> crate::mcp_proxies::types::UpdateMcpProxyRequest {
        serde_json::from_value(serde_json::json!({ "name": name })).unwrap()
    }

    async fn create(
        store: &Arc<MemStore>,
        body: serde_json::Value,
        context: Option<Extension<PatTenantContext>>,
        scope: Option<Extension<PatResourceScope>>,
    ) -> Result<McpProxy, (StatusCode, String)> {
        super::create_mcp_proxy(
            Extension(store.clone()),
            Extension(Arc::new(super::McpServerManager::new())),
            Extension(None),
            Extension(no_resource_owners()),
            None,
            context,
            scope,
            Json(serde_json::from_value(body).unwrap()),
        )
        .await
        .map(|Json(response)| response.proxy)
    }

    fn create_body(id: Option<&str>) -> serde_json::Value {
        let mut body = serde_json::json!({
            "name": "api", "description": "", "base_url": "https://8.8.8.8/v1",
            "openapi_spec": SPEC, "channel_prefix": "/mcp", "endpoint_path": "/api",
            "direct_access": false,
        });
        if let Some(id) = id {
            body["id"] = serde_json::json!(id);
        }
        body
    }

    #[tokio::test]
    async fn a_tenant_cannot_update_or_delete_an_operators_proxy_it_can_read() {
        let store = store_with(vec![owned("op-1", None)]);
        let manager = Arc::new(super::McpServerManager::new());

        let read =
            super::get_mcp_proxy(Extension(store.clone()), Path("op-1".to_string()), tenant("tenant-a"), open_scope())
                .await;
        assert!(read.is_ok(), "reading an operator's proxy stays allowed so a surface can front it");

        let err = super::update_mcp_proxy(
            Extension(store.clone()),
            Extension(manager.clone()),
            Extension(None),
            Extension(no_resource_owners()),
            Path("op-1".to_string()),
            tenant("tenant-a"),
            open_scope(),
            Json(rename("hijacked")),
        )
        .await
        .expect_err("update refused");
        assert_eq!(err.0, StatusCode::FORBIDDEN);

        let err = super::delete_mcp_proxy(
            Extension(store.clone()),
            Extension(manager),
            Extension(None),
            Path("op-1".to_string()),
            tenant("tenant-a"),
            open_scope(),
        )
        .await
        .expect_err("delete refused");
        assert_eq!(err.0, StatusCode::FORBIDDEN);

        let kept = store
            .get("op-1")
            .await
            .unwrap()
            .expect("still there");
        assert_eq!(kept.name, "/op-1", "unchanged");
    }

    #[tokio::test]
    async fn a_tenant_still_manages_its_own_proxy_and_an_operator_still_manages_all() {
        let store =
            store_with(vec![owned("mine", Some("tenant-a")), owned("op-1", None), owned("theirs", Some("tenant-b"))]);
        let manager = Arc::new(super::McpServerManager::new());
        let update = |id: &str, context: Option<Extension<PatTenantContext>>| {
            super::update_mcp_proxy(
                Extension(store.clone()),
                Extension(manager.clone()),
                Extension(None),
                Extension(no_resource_owners()),
                Path(id.to_string()),
                context,
                open_scope(),
                Json(rename("renamed")),
            )
        };

        assert!(
            update("mine", tenant("tenant-a"))
                .await
                .is_ok()
        );
        assert_eq!(
            update("theirs", tenant("tenant-a"))
                .await
                .expect_err("other tenant")
                .0,
            StatusCode::FORBIDDEN
        );
        assert!(
            super::update_mcp_proxy(
                Extension(store.clone()),
                Extension(manager.clone()),
                Extension(None),
                Extension(no_resource_owners()),
                Path("op-1".to_string()),
                None,
                None,
                Json(rename("renamed")),
            )
            .await
            .is_ok(),
            "an appliance-wide caller is unaffected"
        );
        assert!(
            super::delete_mcp_proxy(
                Extension(store.clone()),
                Extension(manager),
                Extension(None),
                Path("mine".to_string()),
                tenant("tenant-a"),
                open_scope(),
            )
            .await
            .is_ok()
        );
        assert!(
            store
                .get("mine")
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn a_caller_chosen_id_is_used_and_confined_by_the_scope() {
        let store = store_with(vec![]);
        let prefixed = scope(r"\ATENANT:tenant-a:mcp-proxies:boris-.*\z");

        let proxy = create(&store, create_body(Some("boris-acct-proj-api")), tenant("tenant-a"), prefixed.clone())
            .await
            .expect("created");
        assert_eq!(proxy.id, "boris-acct-proj-api");
        assert_eq!(proxy.tenant_id.as_deref(), Some("tenant-a"));
        assert!(!proxy.direct_access);

        let err = create(&store, create_body(None), tenant("tenant-a"), prefixed.clone())
            .await
            .expect_err("a minted UUID is outside a prefixed scope");
        assert_eq!(err.0, StatusCode::FORBIDDEN);
        let err = create(&store, create_body(Some("other-api")), tenant("tenant-a"), prefixed)
            .await
            .expect_err("an id outside the prefix");
        assert_eq!(err.0, StatusCode::FORBIDDEN);

        let minted = create(&store, create_body(None), None, None)
            .await
            .expect("no id still mints one");
        assert!(uuid::Uuid::parse_str(&minted.id).is_ok());
    }

    #[tokio::test]
    async fn a_caller_chosen_id_cannot_replace_an_existing_proxy() {
        let store = store_with(vec![owned("op-1", None)]);
        let err = create(&store, create_body(Some("op-1")), tenant("tenant-a"), open_scope())
            .await
            .expect_err("taken");
        assert_eq!(err.0, StatusCode::CONFLICT);
        assert!(
            err.1
                .contains("already exists"),
            "{}",
            err.1
        );
        let kept = store
            .get("op-1")
            .await
            .unwrap()
            .expect("kept");
        assert_eq!(kept.tenant_id, None, "the operator's record is untouched");
    }

    #[tokio::test]
    async fn a_caller_chosen_id_that_is_not_a_plain_name_is_refused() {
        let store = store_with(vec![]);
        for bad in ["", "../escape", "a/b", "a.b", "TENANT:x", "-lead", &"x".repeat(129)] {
            let err = create(&store, create_body(Some(bad)), None, None)
                .await
                .expect_err(bad);
            assert_eq!(err.0, StatusCode::BAD_REQUEST, "{bad:?}");
        }
        assert!(
            store
                .list_all()
                .await
                .unwrap()
                .is_empty()
        );
        assert!(super::is_valid_mcp_proxy_id("0f8fad5b-d9cb-469f-a165-70867728950e"), "a UUID is valid");
        assert!(super::is_valid_mcp_proxy_id(&"x".repeat(128)));
    }

    #[tokio::test]
    async fn a_proxy_may_declare_only_its_own_resource() {
        let store = store_with(vec![]);
        let mut body = create_body(Some("foreign"));
        body["mcp_http"] = serde_json::json!({"authorization": {"resource": "https://gw.example/b", "scopes": []}});
        assert_eq!(
            create(&store, body, None, None)
                .await
                .expect_err("another endpoint's URL")
                .0,
            StatusCode::BAD_REQUEST
        );

        let mut body = create_body(Some("own"));
        body["mcp_http"] =
            serde_json::json!({"authorization": {"resource": "https://gw.example/mcp/api", "scopes": []}});
        create(&store, body, None, None)
            .await
            .expect("its own URL");

        // Moving the proxy keeps the stored resource, which then names a path
        // it no longer serves.
        let err = super::update_mcp_proxy(
            Extension(store.clone()),
            Extension(Arc::new(super::McpServerManager::new())),
            Extension(None),
            Extension(no_resource_owners()),
            Path("own".to_string()),
            None,
            None,
            Json(serde_json::from_value(serde_json::json!({ "endpoint_path": "/moved" })).unwrap()),
        )
        .await
        .expect_err("moved away from its resource");
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
    }

    fn legacy_incompatible_spec() -> String {
        serde_json::json!({
            "openapi": "3.1.0", "info": {"title": "Resources", "version": "1.0"},
            "paths": {"/filter": {"post": {"operationId": "filter", "requestBody": {"required": true,
                "content": {"application/json": {"schema": {
                    "$id": "https://schemas.example/filter", "type": "object",
                    "$defs": {"Proof": {"type": "string"}}, "properties": {"proof": {"$ref": "#/$defs/Proof"}}
                }}}
            }, "responses": {"200": {"description": "OK"}}}}}
        })
        .to_string()
    }

    #[tokio::test]
    async fn create_and_update_warn_when_the_legacy_catalog_is_unavailable() {
        let legacy_incompatible = legacy_incompatible_spec();
        let store = store_with(vec![]);
        let manager = Arc::new(super::McpServerManager::new());
        let mut body = create_body(Some("schema-api"));
        body["openapi_spec"] = serde_json::json!(legacy_incompatible);
        let Json(created) = super::create_mcp_proxy(
            Extension(store.clone()),
            Extension(manager.clone()),
            Extension(None),
            Extension(no_resource_owners()),
            None,
            None,
            None,
            Json(serde_json::from_value(body).unwrap()),
        )
        .await
        .expect("created with a modern-only catalog");
        assert_eq!(created.warnings.len(), 1);
        assert!(created.warnings[0].contains(crate::mcp::MCP_LEGACY_VERSION), "{:?}", created.warnings);
        assert_eq!(serde_json::to_value(&created).unwrap()["warnings"], serde_json::json!(created.warnings));
        assert!(
            store
                .get("schema-api")
                .await
                .unwrap()
                .is_some()
        );

        let update = |spec: &str| {
            super::update_mcp_proxy(
                Extension(store.clone()),
                Extension(manager.clone()),
                Extension(None),
                Extension(no_resource_owners()),
                Path("schema-api".to_string()),
                None,
                None,
                Json(serde_json::from_value(serde_json::json!({ "openapi_spec": spec })).unwrap()),
            )
        };
        let Json(fixed) = update(SPEC)
            .await
            .expect("updated");
        assert!(fixed.warnings.is_empty());
        assert!(
            !serde_json::to_value(&fixed)
                .unwrap()
                .as_object()
                .unwrap()
                .contains_key("warnings")
        );
        let Json(broken) = update(&legacy_incompatible)
            .await
            .expect("updated");
        assert_eq!(broken.warnings, created.warnings);

        let rename = |name: &str| {
            super::update_mcp_proxy(
                Extension(store.clone()),
                Extension(manager.clone()),
                Extension(None),
                Extension(no_resource_owners()),
                Path("schema-api".to_string()),
                None,
                None,
                Json(serde_json::from_value(serde_json::json!({ "name": name })).unwrap()),
            )
        };
        let Json(renamed) = rename("Renamed")
            .await
            .expect("renamed without a reload");
        assert_eq!(renamed.proxy.name, "Renamed");
        assert_eq!(renamed.warnings, created.warnings);

        let failed = update("openapi: [unclosed")
            .await
            .expect_err("an unparseable spec fails the rebuild");
        assert_eq!(failed.0, StatusCode::BAD_REQUEST);
        let Json(after_failure) = rename("After failure")
            .await
            .expect("renamed without a reload");
        assert_eq!(after_failure.warnings, created.warnings);

        let Json(restored) = update(SPEC)
            .await
            .expect("legacy catalog restored");
        assert!(restored.warnings.is_empty());
        let Json(renamed_again) = rename("Renamed again")
            .await
            .expect("renamed without a reload");
        assert!(
            renamed_again
                .warnings
                .is_empty()
        );
    }

    async fn create_with_manager(
        store: &Arc<MemStore>,
        manager: &Arc<super::McpServerManager>,
        body: serde_json::Value,
    ) -> super::McpProxyWriteResponse {
        let Json(created) = super::create_mcp_proxy(
            Extension(store.clone()),
            Extension(manager.clone()),
            Extension(None),
            Extension(no_resource_owners()),
            None,
            None,
            None,
            Json(serde_json::from_value(body).unwrap()),
        )
        .await
        .expect("created");
        created
    }

    async fn discover_proxy(
        store: &Arc<MemStore>,
        manager: &Arc<super::McpServerManager>,
        proxy_id: &str,
    ) -> Result<Vec<String>, (StatusCode, String)> {
        let Json(response) = super::discover_mcp_tools(
            Extension(store.clone()),
            Extension(manager.clone()),
            Extension(None),
            None,
            None,
            Json(DiscoverMcpToolsRequest {
                mcp_proxy_id: Some(proxy_id.to_string()),
                target_endpoint: None,
                target_auth: None,
            }),
        )
        .await?;
        Ok(response
            .tools
            .into_iter()
            .map(|tool| tool.name)
            .collect())
    }

    #[tokio::test]
    async fn tool_discovery_lists_a_modern_only_proxy_from_its_modern_catalog() {
        let store = store_with(vec![]);
        let manager = Arc::new(super::McpServerManager::new());
        let mut body = create_body(Some("schema-api"));
        body["openapi_spec"] = serde_json::json!(legacy_incompatible_spec());
        let created = create_with_manager(&store, &manager, body).await;
        assert_eq!(created.warnings.len(), 1);
        assert!(
            manager
                .get_server("schema-api")
                .await
                .is_none()
        );
        assert_eq!(
            discover_proxy(&store, &manager, "schema-api")
                .await
                .unwrap(),
            vec!["filter".to_string()]
        );

        manager
            .remove_server("schema-api")
            .await;
        assert_eq!(
            discover_proxy(&store, &manager, "schema-api")
                .await
                .unwrap(),
            vec!["filter".to_string()]
        );
        assert!(
            manager
                .get_server("schema-api")
                .await
                .is_none()
        );
    }

    #[tokio::test]
    async fn tool_discovery_lists_a_legacy_capable_proxy_and_rejects_an_unknown_one() {
        let store = store_with(vec![]);
        let manager = Arc::new(super::McpServerManager::new());
        let created = create_with_manager(&store, &manager, create_body(Some("pets-api"))).await;
        assert!(created.warnings.is_empty());
        assert!(
            manager
                .get_server("pets-api")
                .await
                .is_some()
        );
        assert_eq!(
            discover_proxy(&store, &manager, "pets-api")
                .await
                .unwrap(),
            vec!["listPets".to_string()]
        );

        let error = discover_proxy(&store, &manager, "missing-api")
            .await
            .unwrap_err();
        assert_eq!(error.0, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn a_managed_by_label_is_kept_trimmed_and_cleared_on_request() {
        let store = store_with(vec![]);
        let mut body = create_body(Some("boris-a-api"));
        body["managed_by"] = serde_json::json!("  Boris ");
        let proxy = create(&store, body, None, None)
            .await
            .expect("created");
        assert_eq!(proxy.managed_by.as_deref(), Some("Boris"));

        let manager = Arc::new(super::McpServerManager::new());
        let update = |body: serde_json::Value| {
            super::update_mcp_proxy(
                Extension(store.clone()),
                Extension(manager.clone()),
                Extension(None),
                Extension(no_resource_owners()),
                Path("boris-a-api".to_string()),
                None,
                None,
                Json(serde_json::from_value(body).unwrap()),
            )
        };
        let Json(kept) = update(serde_json::json!({ "name": "renamed" }))
            .await
            .expect("updated");
        assert_eq!(
            kept.proxy
                .managed_by
                .as_deref(),
            Some("Boris"),
            "absent keeps the label"
        );
        let Json(cleared) = update(serde_json::json!({ "managed_by": "" }))
            .await
            .expect("cleared");
        assert_eq!(cleared.proxy.managed_by, None);
        assert!(
            !serde_json::to_value(&cleared)
                .unwrap()
                .as_object()
                .unwrap()
                .contains_key("managed_by")
        );

        let mut bad = create_body(Some("boris-b-api"));
        bad["managed_by"] = serde_json::json!("x".repeat(65));
        assert_eq!(
            create(&store, bad, None, None)
                .await
                .expect_err("too long")
                .0,
            StatusCode::BAD_REQUEST
        );
        let mut bad = create_body(Some("boris-c-api"));
        bad["managed_by"] = serde_json::json!("Bo\nris");
        assert_eq!(
            create(&store, bad, None, None)
                .await
                .expect_err("control char")
                .0,
            StatusCode::BAD_REQUEST
        );
    }

    #[test]
    fn stored_and_requested_proxies_default_to_direct_access() {
        let stored: McpProxy = serde_json::from_value(serde_json::json!({
            "id": "p1", "name": "p1", "description": "", "base_url": "https://api.example.com",
            "openapi_spec": "openapi: 3.0.0", "status": "active", "channel_prefix": "/mcp",
            "endpoint_path": "/p1", "created_at": "2026-01-01T00:00:00Z", "updated_at": "2026-01-01T00:00:00Z"
        }))
        .expect("a record written before direct_access existed still loads");
        assert!(stored.direct_access, "existing proxies keep their direct route");
        let request: crate::mcp_proxies::types::CreateMcpProxyRequest = serde_json::from_value(serde_json::json!({
            "name": "p", "description": "", "base_url": "https://api.example.com",
            "openapi_spec": "openapi: 3.0.0", "channel_prefix": "/mcp", "endpoint_path": "/p"
        }))
        .expect("a request without direct_access is valid");
        assert_eq!(request.direct_access, None);
    }
}
