use std::collections::HashMap;
use std::path::{Path, PathBuf};

pub const G2G_BDD_GATEWAY_LOG_LEVEL_ENV: &str = "G2G_BDD_GATEWAY_LOG_LEVEL";

use crate::bdd_support::config::a2a_proxy::{A2aProxyFixture, write_a2a_proxy_fixture};
use crate::bdd_support::config::agent_surface::{AgentSurfaceFixture, write_agent_surface_fixture};
use crate::bdd_support::gateway_process::{GatewayProcess, OutputMode, SURFACE_TEST_AUTH_TOKEN as TEST_AUTH_TOKEN};

use crate::bdd_support::config::api_keys::write_api_key_provider_fixture;
use crate::bdd_support::config::gateway_bootstrap::{
    GatewayBootstrapSurface, write_gateway_bootstrap_json, write_gateway_bootstrap_json_with_outbound_listener,
    write_gateway_bootstrap_json_with_terms,
};
use crate::bdd_support::config::jwt_verification_strategy::write_jwt_verification_strategy_fixture;
use crate::bdd_support::config::mcp_proxy::{McpProxyFixture, write_mcp_proxy_fixture};
use crate::bdd_support::config::policy_definitions::write_policy_definition_fixture;
use crate::bdd_support::config::secrets::write_secret_fixture;
use crate::bdd_support::config::storage::create_storage_dirs;
use crate::bdd_support::config::toml::write_config_toml;
use chrono::{DateTime, Utc};

use serde_json::json;

use tracing::log::Level;

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SecretFixture {
    pub id: String,
    pub value: String,
}

impl SecretFixture {
    pub fn new(
        id: impl Into<String>,
        value: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            value: value.into(),
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct PolicyDefinitionFixture {
    pub id: String,
    pub description: String,
    pub rego: String,
}

impl PolicyDefinitionFixture {
    pub fn new(
        id: impl Into<String>,
        description: impl Into<String>,
        rego: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            description: description.into(),
            rego: rego.into(),
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct JwtVerificationStrategyFixture {
    pub id: String,
    pub name: String,
    pub expected_issuer: String,
    pub jwks_uri: String,
}

impl JwtVerificationStrategyFixture {
    pub fn new(
        id: impl Into<String>,
        name: impl Into<String>,
        expected_issuer: impl Into<String>,
        jwks_uri: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            expected_issuer: expected_issuer.into(),
            jwks_uri: jwks_uri.into(),
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ApiKeyProviderFixture {
    pub id: String,
    pub agent_id: String,
    pub key_id: String,
    pub client_id: String,
    pub secret: String,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct CredentialProviderFixture {
    pub id: String,
    pub name: String,
    pub provider_id: String,
    pub provider_type: String,
    pub authorization_endpoint: Option<String>,
    pub token_endpoint: Option<String>,
    pub client_id_secret_ref: Option<String>,
    pub client_secret_secret_ref: Option<String>,
    pub default_scopes: Vec<String>,
    pub callback_path: String,
    pub callback_url: Option<String>,
    pub token_refresh_enabled: bool,
    pub api_key_secret_ref: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl ApiKeyProviderFixture {
    pub fn new(
        id: impl Into<String>,
        agent_id: impl Into<String>,
        key_id: impl Into<String>,
        client_id: impl Into<String>,
        secret: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            agent_id: agent_id.into(),
            key_id: key_id.into(),
            client_id: client_id.into(),
            secret: secret.into(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct GatewayBootstrapFixture {
    pub key: String,
    pub gateway_port: u16,
    pub identity_route_key: String,
    pub bootstrap_surfaces: Vec<GatewayBootstrapSurface>,
    pub outbound_listener_port: Option<u16>,
    pub agent_surfaces: HashMap<String, AgentSurfaceFixture>,
    pub secrets: HashMap<String, SecretFixture>,
    pub policies: HashMap<String, PolicyDefinitionFixture>,
    pub jwt_strategies: HashMap<String, JwtVerificationStrategyFixture>,
    pub api_key_providers: HashMap<String, ApiKeyProviderFixture>,
    pub credential_providers: HashMap<String, CredentialProviderFixture>,
    pub mcp_proxies: HashMap<String, McpProxyFixture>,
    pub a2a_proxies: HashMap<String, A2aProxyFixture>,
    pub root_dir: Option<PathBuf>,
    pub log_level: Option<Level>,
    pub policy_opa_entry: Option<String>,
    pub terms_enabled: bool,
    pub affinidi_terms_url: Option<String>,
}

impl GatewayBootstrapFixture {
    pub fn new(
        gateway_port: u16,
        identity_route_key: impl Into<String>,
        bootstrap_surfaces: Vec<GatewayBootstrapSurface>,
        key: impl Into<String>,
    ) -> Self {
        Self {
            key: key.into(),
            gateway_port,
            identity_route_key: identity_route_key.into(),
            bootstrap_surfaces,
            outbound_listener_port: None,
            agent_surfaces: HashMap::new(),
            secrets: HashMap::new(),
            policies: HashMap::new(),
            jwt_strategies: HashMap::new(),
            api_key_providers: HashMap::new(),
            credential_providers: HashMap::new(),
            mcp_proxies: HashMap::new(),
            a2a_proxies: HashMap::new(),
            root_dir: None,
            log_level: None,
            policy_opa_entry: None,
            terms_enabled: false,
            affinidi_terms_url: None,
        }
    }

    pub async fn start_gateway(&self) -> GatewayProcess {
        let base_dir = self
            .root_dir
            .as_ref()
            .expect("root dir must be set")
            .as_path();
        write_gateway_config_tree(base_dir, self, false);
        write_config_toml_from_fixture(self);
        self.write_self_record();
        let config_toml_path = base_dir.join("config.toml");
        let inbound_port = self.gateway_port;
        let mut gateway = GatewayProcess::start(&config_toml_path, base_dir, TEST_AUTH_TOKEN, OutputMode::Piped);
        gateway = gateway.with_port(inbound_port);
        gateway
            .wait_until_ready()
            .await;
        gateway
    }

    pub fn write_self_record(&self) {
        let base_dir = self
            .root_dir
            .as_ref()
            .expect("root dir must be set")
            .as_path();
        let gateway_record_dir = base_dir.join("_storage/gateways");
        let record_path = gateway_record_dir.join(format!("{}.json", self.key));
        let now = Utc::now().to_rfc3339();
        let record_json = json!({
            "id": &self.key,
            "name": &self.key,
            "description": &self.key,
            "did": format!("did:localhost%3a{}", self.gateway_port),
            "gateway_type": "self",
            "status": "active",
            "created_at": now,
            "updated_at": now,
            "creation_type": "user",
            "exposed_channels": [],
            "opa_policy_config": if let Some(policy_opa_entry) = &self.policy_opa_entry {
                json!({
                    "enabled": true,
                    "policy": policy_opa_entry,
                })
            } else {
                serde_json::Value::Null
            },
        });

        std::fs::write(record_path, serde_json::to_string_pretty(&record_json).unwrap()).unwrap();
    }
}

pub fn write_gateway_config_tree(
    base_dir: &Path,
    fixture: &GatewayBootstrapFixture,
    with_toml: bool,
) {
    let storage_dir = base_dir.join("_storage");
    create_storage_dirs(&storage_dir);

    let bootstrap_surfaces = fixture
        .bootstrap_surfaces
        .iter()
        .map(|s| GatewayBootstrapSurface::new(&s.id, &s.name, &s.prefix))
        .collect::<Vec<_>>();

    let other_bootstrap_surfaces = fixture
        .agent_surfaces
        .values()
        .map(|s| GatewayBootstrapSurface::new(&s.name, &s.name, &s.access_point.route))
        .collect::<Vec<_>>();

    let bootstrap_surfaces = if bootstrap_surfaces.is_empty() {
        other_bootstrap_surfaces
    } else {
        bootstrap_surfaces
    };

    if let Some(outbound_port) = fixture.outbound_listener_port {
        write_gateway_bootstrap_json_with_outbound_listener(
            base_dir,
            fixture.gateway_port,
            outbound_port,
            &bootstrap_surfaces,
            &fixture.identity_route_key,
        );
    } else if fixture.terms_enabled {
        write_gateway_bootstrap_json_with_terms(
            base_dir,
            fixture.gateway_port,
            &bootstrap_surfaces,
            &fixture.identity_route_key,
            fixture
                .affinidi_terms_url
                .as_deref()
                .expect("Terms-enabled fixture requires an Affinidi Terms URL"),
        );
    } else {
        write_gateway_bootstrap_json(base_dir, fixture.gateway_port, &bootstrap_surfaces, &fixture.identity_route_key);
    }

    let surfaces_dir = storage_dir.join("agent_surfaces");
    for surface in fixture
        .agent_surfaces
        .values()
    {
        write_agent_surface_fixture(&surfaces_dir, surface);
    }

    let secrets_dir = storage_dir.join("secrets");
    for secret in fixture.secrets.values() {
        write_secret_fixture(&secrets_dir, &secret.id, &secret.value);
    }

    let policies_dir = storage_dir.join("policies");
    for policy in fixture.policies.values() {
        write_policy_definition_fixture(&policies_dir, &policy.id, &policy.description, &policy.rego);
    }

    let strategies_dir = storage_dir.join("jwt_verification_strategies");
    for strategy in fixture
        .jwt_strategies
        .values()
    {
        write_jwt_verification_strategy_fixture(
            &strategies_dir,
            &strategy.id,
            &strategy.name,
            &strategy.expected_issuer,
            &strategy.jwks_uri,
        );
    }

    let api_keys_dir = storage_dir.join("api_keys");
    for api_key_provider in fixture
        .api_key_providers
        .values()
    {
        write_api_key_provider_fixture(
            &api_keys_dir,
            &api_key_provider.agent_id,
            &api_key_provider.key_id,
            &api_key_provider.client_id,
            &api_key_provider.secret,
        );
    }

    let credential_providers_dir = storage_dir.join("credential_providers");
    for provider in fixture
        .credential_providers
        .values()
    {
        write_credential_provider_fixture(&credential_providers_dir, provider);
    }

    let proxies_dir = storage_dir.join("mcp_proxies");
    for proxy in fixture.mcp_proxies.values() {
        write_mcp_proxy_fixture(&proxies_dir, proxy);
    }

    let a2a_proxies_dir = storage_dir.join("a2a_proxies");
    for proxy in fixture.a2a_proxies.values() {
        write_a2a_proxy_fixture(&a2a_proxies_dir, proxy);
    }
    if with_toml {
        write_config_toml(base_dir, &storage_dir);
    }
}

fn write_config_toml_from_fixture(gateway_fixture: &GatewayBootstrapFixture) {
    let certs_dir = crate::bdd_support::config::dev_certs::dev_cert_dir();
    let log_level = gateway_log_level(gateway_fixture.log_level)
        .as_str()
        .to_lowercase();
    let config_dir = gateway_fixture
        .root_dir
        .as_ref()
        .expect("root dir must be set");
    let storage_dir = config_dir.join("_storage");
    // Backup key is required at startup; a deterministic literal hex test key.
    let backup_key = "00".repeat(32);
    let config_toml = format!(
        r#"channel_config_source = "local"
secrets_backend = "filesystem"
auth_mode = "passkey"
session_timeout_minutes = 20
websocket_require_auth = false
metrics_retention_minutes = 360
metrics_cache_ttl_seconds = 1
backup_encryption_key = "{backup_key}"

[a2a]
fabric_gateway_timeout_ms = 5000
message_expires_seconds = 15

[config_files]
gateway = "{gateway_json_path}"

[storage_paths]
config_cache = "{storage}/cache"
settings = "{storage}/settings"
notifications = "{storage}/notifications/messages"
notification_templates = "{storage}/notifications/templates"
connection_points = "{storage}/connection_points"
agent_surfaces = "{storage}/agent_surfaces"
secrets = "{storage}/secrets"
apikeys = "{storage}/apikeys"
certificates = "{storage}/certificates"
mcp_proxies = "{storage}/mcp_proxies"
a2a_proxies = "{storage}/a2a_proxies"
pipes = "{storage}/pipes"
integrations = "{storage}/integrations/definitions"
integration_triggers = "{storage}/integrations/triggers"
webhooks = "{storage}/webhooks"
vc_keys = "{storage}/vc_keys"
metrics = "{storage}/metrics"
passkeys = "{storage}/passkeys"
avatars = "{storage}/avatars"
identities = "{storage}/identities"
gateways = "{storage}/gateways"
mediators = "{storage}/mediators"
trust_registries = "{storage}/trust_registries"
messages = "{storage}/messages"
x402_transactions = "{storage}/x402_transactions"
sessions = "{storage}/sessions"
policy_definitions = "{storage}/policies"
issuers = "{storage}/issuers"
backup_restore = "{storage}/backup_restore"
system_metrics = "{storage}/system_metrics"
mpp_transactions = "{storage}/mpp_transactions"

[did_cache]
ttl_seconds = 3600
max_entries = 100
stale_threshold_percent = 80
storage_path = "{storage}/cache/did"

[tls]
cert_path = "{cert}"
key_path = "{key}"
verify_upstream = false

[logging]
level = "{log_level}"
log_directory = "{storage}/logs"
json = false
"#,
        gateway_json_path = config_dir
            .join("gateway.json")
            .display(),
        storage = storage_dir.display(),
        cert = certs_dir
            .join("cert.pem")
            .display(),
        key = certs_dir
            .join("key.pem")
            .display(),
    );
    std::fs::write(config_dir.join("config.toml"), config_toml).unwrap();
}

pub fn gateway_log_level(fixture_level: Option<Level>) -> Level {
    match std::env::var(G2G_BDD_GATEWAY_LOG_LEVEL_ENV) {
        Ok(value) => value
            .parse::<Level>()
            .unwrap_or_else(|_| fixture_level.unwrap_or(Level::Error)),
        Err(_) => fixture_level.unwrap_or(Level::Error),
    }
}

fn write_credential_provider_fixture(
    dir: &Path,
    provider: &CredentialProviderFixture,
) {
    std::fs::create_dir_all(dir).unwrap();
    let mut value = serde_json::json!({
        "id": provider.id,
        "name": provider.name,
        "provider_id": provider.provider_id,
        "provider_type": provider.provider_type,
        "default_scopes": provider.default_scopes,
        "callback_path": provider.callback_path,
        "token_refresh_enabled": provider.token_refresh_enabled,
        "additional_params": {},
        "created_at": provider.created_at.to_rfc3339(),
        "updated_at": provider.updated_at.to_rfc3339(),
    });
    if let Some(endpoint) = &provider.authorization_endpoint {
        value["authorization_endpoint"] = serde_json::json!(endpoint);
    }
    if let Some(endpoint) = &provider.token_endpoint {
        value["token_endpoint"] = serde_json::json!(endpoint);
    }
    if let Some(secret_ref) = &provider.client_id_secret_ref {
        value["client_id_secret_ref"] = serde_json::json!(secret_ref);
    }
    if let Some(secret_ref) = &provider.client_secret_secret_ref {
        value["client_secret_secret_ref"] = serde_json::json!(secret_ref);
    }
    if let Some(callback_url) = &provider.callback_url {
        value["callback_url"] = serde_json::json!(callback_url);
    }
    if let Some(secret_ref) = &provider.api_key_secret_ref {
        value["api_key_secret_ref"] = serde_json::json!(secret_ref);
    }
    std::fs::write(dir.join(format!("{}.json", provider.id)), serde_json::to_string_pretty(&value).unwrap()).unwrap();
}

#[cfg(test)]
mod tests {
    #[test]
    fn gateway_config_tree_writer_creates_shared_gateway_fixture_tree() {
        let temp_dir = tempfile::TempDir::new().unwrap();
        let bootstrap_surfaces = vec![super::GatewayBootstrapSurface::new("alpha", "Alpha", "/alpha")];
        let mut config_tree =
            super::GatewayBootstrapFixture::new(32001, "identity", bootstrap_surfaces, "test-gateway");
        config_tree
            .agent_surfaces
            .insert(
                "alpha".to_string(),
                super::AgentSurfaceFixture::new(
                    "alpha",
                    "Alpha",
                    "BDD surface",
                    "http://localhost:32001",
                    "/alpha",
                    "a2a",
                    "http://127.0.0.1:9",
                ),
            );
        config_tree
            .secrets
            .insert("source-secret".to_string(), super::SecretFixture::new("source-secret", "valid"));
        config_tree.policies.insert(
            "alpha-inbound-policy".to_string(),
            super::PolicyDefinitionFixture::new(
                "alpha-inbound-policy",
                "BDD inbound policy",
                "package policy\ndefault allow := true",
            ),
        );

        super::write_gateway_config_tree(temp_dir.path(), &config_tree, true);

        let config_toml = std::fs::read_to_string(
            temp_dir
                .path()
                .join("config.toml"),
        )
        .unwrap();
        assert!(config_toml.contains("gateway.json"));

        let gateway_json: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(
                temp_dir
                    .path()
                    .join("gateway.json"),
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(gateway_json["listeners"][0]["port"], 32001);
        assert_eq!(gateway_json["channels"][0]["id"], "alpha");

        let surface_json: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(
                temp_dir
                    .path()
                    .join("_storage/agent_surfaces/alpha.json"),
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(surface_json["surface_id"], "alpha");
        assert_eq!(surface_json["target"]["endpoint"], "http://127.0.0.1:9");

        let secret_json: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(
                temp_dir
                    .path()
                    .join("_storage/secrets/source-secret.json"),
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(secret_json["value"], "valid");

        let policy_json: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(
                temp_dir
                    .path()
                    .join("_storage/policies/alpha-inbound-policy.json"),
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(policy_json["policy"], "package policy\ndefault allow := true");
    }
}
