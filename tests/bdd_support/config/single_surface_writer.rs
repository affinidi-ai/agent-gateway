use std::collections::HashSet;
use std::path::Path;

use crate::bdd_support::config::DEFAULT_HEADER_METADATA_EXTENSION_URI;
use crate::bdd_support::config::a2a_proxy::A2aProxyFixture;
use crate::bdd_support::config::agent_surface::AgentSurfaceFixture;
use crate::bdd_support::config::config_tree::{
    ApiKeyProviderFixture, CredentialProviderFixture, GatewayBootstrapFixture, JwtVerificationStrategyFixture,
    PolicyDefinitionFixture, SecretFixture, write_gateway_config_tree,
};
use crate::bdd_support::config::gateway_bootstrap::GatewayBootstrapSurface;
use crate::bdd_support::config::mcp_proxy::McpProxyFixture;
use crate::bdd_support::config::single_surface_fixture::{
    CredentialProviderKind, DelegatedCredentialInjection, DidWebVhIdentityFixture, SurfaceConfigBuilder,
    SurfaceSourceAuthConfig,
};
use crate::bdd_support::config::target_auth::static_secret_target_auth_json;

struct SingleSurfaceOptions<'a> {
    outbound: Option<(u16, &'a str)>,
    affinidi_terms_url: Option<&'a str>,
}

pub fn write_single_surface_config(
    base_dir: &Path,
    gateway_port: u16,
    mock_url: &str,
    surface_config: &SurfaceConfigBuilder,
    jwks_fixture: Option<&JwksFiles>,
) {
    write_single_surface_config_inner(
        base_dir,
        gateway_port,
        mock_url,
        surface_config,
        jwks_fixture,
        SingleSurfaceOptions {
            outbound: None,
            affinidi_terms_url: None,
        },
    );
}

pub fn write_single_surface_config_with_terms(
    base_dir: &Path,
    gateway_port: u16,
    mock_url: &str,
    affinidi_terms_url: &str,
    surface_config: &SurfaceConfigBuilder,
    jwks_fixture: Option<&JwksFiles>,
) {
    write_single_surface_config_inner(
        base_dir,
        gateway_port,
        mock_url,
        surface_config,
        jwks_fixture,
        SingleSurfaceOptions {
            outbound: None,
            affinidi_terms_url: Some(affinidi_terms_url),
        },
    );
}

pub fn write_single_surface_config_with_outbound_listener(
    base_dir: &Path,
    gateway_port: u16,
    outbound_port: u16,
    mock_url: &str,
    transit_target_url: &str,
    surface_config: &SurfaceConfigBuilder,
    jwks_fixture: Option<&JwksFiles>,
) {
    write_single_surface_config_inner(
        base_dir,
        gateway_port,
        mock_url,
        surface_config,
        jwks_fixture,
        SingleSurfaceOptions {
            outbound: Some((outbound_port, transit_target_url)),
            affinidi_terms_url: None,
        },
    );
}

fn write_single_surface_config_inner(
    base_dir: &Path,
    gateway_port: u16,
    mock_url: &str,
    surface_config: &SurfaceConfigBuilder,
    jwks_fixture: Option<&JwksFiles>,
    options: SingleSurfaceOptions<'_>,
) {
    let (outbound_port, transit_target_url) = options
        .outbound
        .map_or((None, None), |(port, url)| (Some(port), Some(url)));
    let mut surface_routes = surface_config
        .registered_routes
        .clone();
    if !surface_routes.contains(&surface_config.route) {
        surface_routes.push(surface_config.route.clone());
    }
    let mut seen_routes = HashSet::new();
    surface_routes.retain(|route| seen_routes.insert(route.clone()));

    let bootstrap_surfaces = surface_routes
        .iter()
        .enumerate()
        .map(|(idx, route)| {
            let id = format!("bdd-surface-{idx}");
            GatewayBootstrapSurface::new(id.clone(), id, route.clone())
        })
        .collect::<Vec<_>>();
    let mut config_tree = GatewayBootstrapFixture::new(gateway_port, "api", bootstrap_surfaces, "");
    config_tree.outbound_listener_port = outbound_port;
    config_tree.terms_enabled = options
        .affinidi_terms_url
        .is_some();
    config_tree.affinidi_terms_url = options
        .affinidi_terms_url
        .map(str::to_string);

    let surface_name = surface_config
        .surface_name
        .as_deref()
        .unwrap_or("bdd-surface");
    let effective_target_url = if let Some(proxy) = &surface_config.mcp_proxy_target {
        format!("proxy://{}", proxy.proxy_id)
    } else if let Some(proxy) = &surface_config.a2a_proxy_target {
        format!("a2a-proxy://{}", proxy.proxy_id)
    } else {
        surface_config
            .override_target_url
            .clone()
            .unwrap_or_else(|| mock_url.to_string())
    };
    let mut surface_fixture = AgentSurfaceFixture::new(
        "bdd-surface",
        surface_name,
        "BDD test surface",
        format!("http://localhost:{gateway_port}"),
        surface_config.route.clone(),
        surface_config
            .protocol
            .clone(),
        effective_target_url,
    );
    if let Some(proxy) = &surface_config.mcp_proxy_target {
        surface_fixture = surface_fixture.with_mcp_proxy_id(&proxy.proxy_id);
    }
    if let Some(proxy) = &surface_config.a2a_proxy_target {
        surface_fixture = surface_fixture.with_a2a_proxy_id(&proxy.proxy_id);
    }
    if let Some(path) = &surface_config.agent_card_path {
        surface_fixture = surface_fixture.with_agent_card_path(path);
    }
    if let Some(auth) = &surface_config.source_auth {
        let method = crate::bdd_support::config::source_auth::caller_authentication_method_json(auth);
        surface_fixture = surface_fixture.with_caller_auth_method(method);
    }
    if let Some(target_auth) = &surface_config.target_auth {
        surface_fixture = surface_fixture.with_target_auth(static_secret_target_auth_json(
            &target_auth.secret_id,
            &target_auth.header_name,
            &target_auth.header_format,
            &target_auth.fallback,
        ));
    }
    if let Some(policy) = &surface_config.mcp_tool_policy {
        surface_fixture = surface_fixture.with_mcp_tool_policy(&policy.allowed_tool, &policy.policy_definition_id);
    }
    if let Some(policy) = &surface_config.mcp_wildcard_tool_policy {
        surface_fixture = surface_fixture.with_mcp_tool_policy("*", &policy.policy_definition_id);
    }
    if let Some(gating) = &surface_config.mcp_tool_gating {
        surface_fixture = surface_fixture.with_mcp_tool_gating(gating.clone());
    }
    if let Some(mcp_http) = &surface_config.mcp_http {
        surface_fixture = surface_fixture.with_mcp_http(mcp_http.clone());
    }
    if let Some(a2a) = &surface_config.a2a_settings {
        surface_fixture = surface_fixture.with_a2a_settings(a2a.clone());
    }
    if let Some(policy) = &surface_config.request_policy {
        surface_fixture = surface_fixture.with_target_policy_definition_id(&policy.id);
    }
    if let Some(cm) = &surface_config.custom_metadata {
        let mut payload = serde_json::Map::new();
        payload.insert(cm.key.clone(), serde_json::Value::String(cm.value.clone()));
        surface_fixture = surface_fixture.with_custom_metadata(serde_json::json!({
            "enabled": true,
            "payload": payload,
            "injection_target": cm.injection_target.clone()
        }));
    }
    if let Some(delegation) = &surface_config.credential_delegation {
        let required_for = match &delegation.required_tool {
            Some(tool) => serde_json::json!({ "tools": [tool] }),
            None => serde_json::json!("all"),
        };
        let inject_as = match &delegation.inject_as {
            DelegatedCredentialInjection::BearerHeader => serde_json::json!({ "type": "bearer_header" }),
            DelegatedCredentialInjection::CustomHeader { name, format } => {
                serde_json::json!({ "type": "custom_header", "name": name, "format": format })
            }
            DelegatedCredentialInjection::Meta { field } => serde_json::json!({ "type": "meta", "field": field }),
        };
        surface_fixture = surface_fixture.with_outbound_credential(serde_json::json!({
            "credential_provider_id": delegation.provider_id,
            "scopes": delegation.scopes,
            "required_for": required_for,
            "consent_mode": "on_demand",
            "inject_as": inject_as,
        }));
    }
    if let Some(transit_point) = &surface_config.transit_point {
        let outbound_port = outbound_port.expect("outbound_port is required when a Transit Point is configured");
        let target_endpoint =
            transit_target_url.expect("transit_target_url is required when a Transit Point is configured");
        let mut transit_point_json = serde_json::json!({
            "name": transit_point.alias,
            "alias": transit_point.alias,
            "target_endpoint": target_endpoint,
            "protocol": transit_point.protocol,
            "listen_path": format!("/transit/{}", transit_point.alias),
            "require_transit_token": false
        });
        if !transit_point
            .header_metadata_mapping
            .headers
            .is_empty()
        {
            transit_point_json["header_metadata_mapping"] = serde_json::json!({
                "extension_uri": DEFAULT_HEADER_METADATA_EXTENSION_URI,
                "strip_mapped_headers": transit_point.header_metadata_mapping.strip_mapped_headers,
                "headers": transit_point.header_metadata_mapping.headers.iter().map(|row| {
                    serde_json::json!({
                        "header": &row.header,
                        "field": &row.field,
                    })
                }).collect::<Vec<_>>()
            });
        }
        if let Some(managed_identity) = &transit_point.managed_identity {
            let mut properties = serde_json::Map::new();
            for field in &managed_identity.fields {
                properties.insert(field.clone(), serde_json::json!({ "type": "string", "x-identity": true }));
            }
            transit_point_json["managed_identity"] = serde_json::json!({
                "type": "payload_extraction",
                "extension_uri": DEFAULT_HEADER_METADATA_EXTENSION_URI,
                "meta_field": "agentIdentity",
                "fields": &managed_identity.fields,
                "json_schema": {
                    "type": "object",
                    "properties": properties,
                    "required": &managed_identity.fields,
                }
            });
            transit_point_json["identity_injection"] = serde_json::json!({
                "inject_vp": true,
            });
        }
        let mut transit_json = serde_json::json!({
            "outbound_listen_address": format!("http://localhost:{outbound_port}"),
            "points": [transit_point_json]
        });
        if let Some(policy) = &surface_config.transit_shared_policy {
            transit_json["opa_policy_definition_id"] = serde_json::json!(policy.id);
        }
        surface_fixture = surface_fixture.with_transit(transit_json);
    }
    for element in &surface_config.caller_trust_check_list {
        surface_fixture = surface_fixture.with_caller_trust_check_element(element.clone());
    }
    for element in &surface_config.target_trust_check_list {
        surface_fixture = surface_fixture.with_target_trust_check_element(element.clone());
    }
    if let Some(identity) = &surface_config.didwebvh_identity {
        surface_fixture = surface_fixture.with_didwebvh_identity_id(
            identity
                .identity_id
                .to_string(),
        );
        write_didwebvh_identity_file(&base_dir.join("_storage"), identity);
    }

    let mut identity_payload_schema = surface_config
        .mcp_identity_payload_schema
        .clone()
        .unwrap_or_else(crate::bdd_support::config::managed_identity::default_identity_payload_schema);
    if surface_config
        .required_mcp_identity_field
        .as_deref()
        == Some("softwareInfo.name")
    {
        identity_payload_schema["required"] = serde_json::json!(["softwareInfo"]);
        identity_payload_schema["properties"]["softwareInfo"]["required"] = serde_json::json!(["name"]);
    }
    if surface_config
        .constrained_mcp_identity_field
        .as_deref()
        == Some("softwareInfo.name")
    {
        identity_payload_schema["properties"]["softwareInfo"]["properties"]["name"]["enum"] =
            serde_json::json!(["planner", "researcher", "caller-agent"]);
    }
    let wrapped_identity_schema = |meta_field: &str| {
        serde_json::json!({
            "type": "object",
            "properties": {
                meta_field: identity_payload_schema.clone()
            },
            "required": [meta_field]
        })
    };
    if surface_config.managed_identity {
        surface_fixture = surface_fixture.with_target_identity_injection(
            crate::bdd_support::config::managed_identity::target_identity_injection_json(&identity_payload_schema),
        );

        if surface_config.protocol == "mcp" {
            let mut protected_slot = serde_json::json!({
                "type": "payload_extraction",
                "meta_field": "serverIdentity",
                "fields": ["serverIdentity.softwareInfo.name", "serverIdentity.softwareInfo.version", "serverIdentity.cloudProvider"],
                "json_schema": identity_payload_schema.clone()
            });
            if surface_config.managed_identity_strip_raw {
                protected_slot["strip_raw_meta"] = serde_json::json!(true);
            }
            surface_fixture = surface_fixture.with_identity_slot("protected", protected_slot);
        }
    }

    if surface_config.mcp_inbound_identity {
        let mut inbound_slot = serde_json::json!({
            "type": "payload_extraction",
            "meta_field": "agentIdentity",
            "fields": ["agentIdentity.softwareInfo.name", "agentIdentity.softwareInfo.version", "agentIdentity.cloudProvider"],
            "json_schema": wrapped_identity_schema("agentIdentity")
        });
        if surface_config.mcp_inbound_identity_strip_raw {
            inbound_slot["strip_raw_meta"] = serde_json::json!(true);
        }
        surface_fixture = surface_fixture.with_identity_slot("inbound", inbound_slot);
    }

    if surface_config.seed_surface {
        config_tree
            .agent_surfaces
            .insert(
                surface_fixture
                    .surface_id
                    .clone(),
                surface_fixture,
            );
    }

    if let Some(jwks) = jwks_fixture {
        config_tree
            .jwt_strategies
            .insert(
                "bdd-jwt-strategy".to_string(),
                JwtVerificationStrategyFixture::new(
                    "bdd-jwt-strategy",
                    "BDD EdDSA Test",
                    jwks.issuer.clone(),
                    format!("{}/.well-known/jwks.json", jwks.issuer),
                ),
            );
    }

    config_tree.secrets.extend(
        secret_fixtures(surface_config)
            .into_iter()
            .map(|secret| (secret.id.clone(), secret)),
    );
    config_tree
        .api_key_providers
        .extend(
            api_key_provider_fixtures(surface_config)
                .into_iter()
                .map(|provider| (provider.id.clone(), provider)),
        );
    config_tree
        .credential_providers
        .extend(
            credential_provider_fixtures(surface_config)
                .into_iter()
                .map(|provider| (provider.id.clone(), provider)),
        );
    config_tree.policies.extend(
        policy_fixtures(surface_config)
            .into_iter()
            .map(|policy| (policy.id.clone(), policy)),
    );

    if let Some(proxy) = &surface_config.mcp_proxy_target {
        let mut fixture = McpProxyFixture::new(&proxy.proxy_id, mock_url);
        if let Some(spec) = &proxy.openapi_spec {
            fixture = fixture.with_openapi_spec(spec.clone());
        }
        if proxy.disabled {
            fixture = fixture.with_disabled();
        }
        config_tree
            .mcp_proxies
            .insert(fixture.proxy_id.clone(), fixture);
    }
    if let Some(proxy) = &surface_config.a2a_proxy_target {
        let mut fixture = A2aProxyFixture::new(
            &proxy.proxy_id,
            &proxy.proxy_id,
            &proxy.secret_id,
            format!("{mock_url}/v3/directline"),
        );
        if proxy.disabled {
            fixture = fixture.with_disabled();
        }
        if proxy.no_answer {
            fixture = fixture.with_fast_timeout();
        }
        config_tree
            .a2a_proxies
            .insert(fixture.proxy_id.clone(), fixture);
    }

    write_gateway_config_tree(base_dir, &config_tree, true);
}

pub struct JwksFiles {
    pub issuer: String,
}

/// Drops a minimal `DidWebVhIdentity` JSON record into the path the runtime
/// reads at boot: `{storage_dir}/identities/didwebvh/{uuid}.json`. The shape
/// matches `crate::identity::didwebvh::DidWebVhIdentity`'s serde layout.
fn write_didwebvh_identity_file(
    storage_dir: &Path,
    identity: &DidWebVhIdentityFixture,
) {
    let didwebvh_dir = storage_dir
        .join("identities")
        .join("didwebvh");
    std::fs::create_dir_all(&didwebvh_dir).expect("create didwebvh identity dir");

    let now = chrono::Utc::now().to_rfc3339();
    let mut metadata = serde_json::Map::new();
    if let Some(dna) = &identity.agent_dna {
        metadata.insert("agentDNA".to_string(), serde_json::Value::String(dna.clone()));
    }

    let record = serde_json::json!({
        "id": identity.identity_id.to_string(),
        "did": identity.did,
        "version": 1,
        "created_at": now,
        "updated_at": now,
        "metadata": metadata,
        "active": true,
    });
    std::fs::write(
        didwebvh_dir.join(format!("{}.json", identity.identity_id)),
        serde_json::to_string_pretty(&record).expect("serialise didwebvh identity"),
    )
    .expect("write didwebvh identity file");
}

fn secret_fixtures(surface_config: &SurfaceConfigBuilder) -> Vec<SecretFixture> {
    let mut secrets = Vec::new();
    if let Some(SurfaceSourceAuthConfig::ApiKey(config)) = &surface_config.source_auth {
        secrets.push(SecretFixture::new(&config.secret_id, &config.valid_key));
    }
    if let Some(SurfaceSourceAuthConfig::ApiKey(config)) = &surface_config.alternate_variant_source_auth {
        secrets.push(SecretFixture::new(&config.secret_id, &config.valid_key));
    }

    if let Some(target_auth) = &surface_config.target_auth
        && let Some(secret_value) = &target_auth.secret_value
    {
        secrets.push(SecretFixture::new(&target_auth.secret_id, secret_value));
    }
    if let Some(proxy) = &surface_config.a2a_proxy_target {
        secrets.push(SecretFixture::new(&proxy.secret_id, &proxy.secret_value));
    }
    if let Some(delegation) = &surface_config.credential_delegation {
        match &delegation.provider_kind {
            CredentialProviderKind::OAuth2AuthorizationCode => {
                secrets.push(SecretFixture::new(format!("bdd-{}-client-id", delegation.provider_id), "bdd-client-id"));
                secrets.push(SecretFixture::new(
                    format!("bdd-{}-client-secret", delegation.provider_id),
                    "bdd-client-secret",
                ));
            }
            CredentialProviderKind::ApiKey { secret_id, secret_value } => {
                secrets.push(SecretFixture::new(secret_id, secret_value));
            }
        }
    }
    secrets
}

fn api_key_provider_fixtures(surface_config: &SurfaceConfigBuilder) -> Vec<ApiKeyProviderFixture> {
    let mut api_key_providers = Vec::new();
    if let Some(SurfaceSourceAuthConfig::ApiKeyProvider(config)) = &surface_config.source_auth {
        api_key_providers.push(ApiKeyProviderFixture::new(
            format!("key-provider-{}-{}", config.agent_id, config.key_id),
            &config.agent_id,
            &config.key_id,
            &config.client_id,
            &config.valid_key,
        ));
    }
    api_key_providers
}

fn credential_provider_fixtures(surface_config: &SurfaceConfigBuilder) -> Vec<CredentialProviderFixture> {
    let Some(delegation) = &surface_config.credential_delegation else {
        return Vec::new();
    };
    let now = chrono::Utc::now();
    let provider_id = delegation.provider_id.clone();
    let provider = match &delegation.provider_kind {
        CredentialProviderKind::OAuth2AuthorizationCode => {
            let base_url = surface_config
                .oauth_provider_base_url
                .as_ref()
                .expect("OAuth provider base URL must be configured before writing credential provider fixture");
            CredentialProviderFixture {
                id: provider_id.clone(),
                name: provider_id.clone(),
                provider_id: provider_id.clone(),
                provider_type: "oauth2_authorization_code".to_string(),
                authorization_endpoint: Some(format!("{base_url}/authorize")),
                token_endpoint: Some(format!("{base_url}/token")),
                client_id_secret_ref: Some(format!("bdd-{provider_id}-client-id")),
                client_secret_secret_ref: Some(format!("bdd-{provider_id}-client-secret")),
                default_scopes: delegation.scopes.clone(),
                callback_path: format!("/v1/identity/oauth/callback/{provider_id}"),
                callback_url: surface_config
                    .oauth_callback_base_url
                    .as_ref()
                    .map(|base| format!("{base}/v1/identity/oauth/callback/{provider_id}")),
                token_refresh_enabled: true,
                api_key_secret_ref: None,
                created_at: now,
                updated_at: now,
            }
        }
        CredentialProviderKind::ApiKey { secret_id, .. } => CredentialProviderFixture {
            id: provider_id.clone(),
            name: provider_id.clone(),
            provider_id: provider_id.clone(),
            provider_type: "api_key".to_string(),
            authorization_endpoint: None,
            token_endpoint: None,
            client_id_secret_ref: None,
            client_secret_secret_ref: None,
            default_scopes: Vec::new(),
            callback_path: String::new(),
            callback_url: None,
            token_refresh_enabled: false,
            api_key_secret_ref: Some(secret_id.clone()),
            created_at: now,
            updated_at: now,
        },
    };
    vec![provider]
}

fn policy_fixtures(surface_config: &SurfaceConfigBuilder) -> Vec<PolicyDefinitionFixture> {
    let mut policies = Vec::new();
    if let Some(policy) = &surface_config.mcp_tool_policy {
        policies.push(PolicyDefinitionFixture::new(
            &policy.policy_definition_id,
            format!("BDD {}", policy.policy_definition_id),
            &policy.rego,
        ));
    }
    if let Some(policy) = &surface_config.mcp_wildcard_tool_policy {
        policies.push(PolicyDefinitionFixture::new(
            &policy.policy_definition_id,
            format!("BDD {}", policy.policy_definition_id),
            &policy.rego,
        ));
    }
    if let Some(policy) = &surface_config.request_policy {
        policies.push(policy.clone());
    }
    if let Some(policy) = &surface_config.mcp_tool_gating_condition_policy {
        policies.push(policy.clone());
    }
    if let Some(policy) = &surface_config.transit_shared_policy {
        policies.push(policy.clone());
    }
    if let Some(policy) = &surface_config.alternate_variant_inbound_policy {
        policies.push(PolicyDefinitionFixture::new(
            &policy.policy_definition_id,
            format!("BDD {}", policy.policy_definition_id),
            &policy.rego,
        ));
    }
    if let Some(policy) = &surface_config.alternate_variant_target_policy {
        policies.push(PolicyDefinitionFixture::new(
            &policy.policy_definition_id,
            format!("BDD {}", policy.policy_definition_id),
            &policy.rego,
        ));
    }
    policies
}
