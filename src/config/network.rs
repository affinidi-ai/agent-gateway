//! Network configuration types for defining listeners, routes, and paths

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use url::Url;

/// Network configuration containing all listeners and their routes
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    /// DID configuration
    pub did: DidConfig,

    /// Require human users to accept applicable Terms before product access.
    #[serde(default)]
    pub terms: bool,

    /// Affinidi Well endpoint serving the current Affinidi T&C metadata.
    #[serde(default)]
    pub affinidi_terms_url: Option<Url>,

    /// WebAuthn configuration
    pub webauthn: WebAuthnConfig,

    /// Integration configuration (types and categories with metadata)
    pub integration: crate::config::IntegrationConfig,

    /// x402 facilitator mode configuration (gateway-level control)
    #[serde(default)]
    pub facilitator_mode: Option<crate::config::types::FacilitatorMode>,

    /// Encryption at rest configuration
    #[serde(default)]
    pub encryption: Option<crate::config::EncryptionConfig>,

    /// CORS origins allowed to access the API
    #[serde(default)]
    pub cors: Vec<String>,

    /// List of port listeners to bind
    pub listeners: Vec<Listener>,

    /// Available channel prefixes for proxy routes
    #[serde(default)]
    pub channels: Vec<ChannelPrefix>,

    /// Available MCP proxy prefixes for MCP tool routes.
    /// Authoritative home for MCP-proxy route prefixes (declared in `gateway.json`).
    #[serde(default)]
    pub mcp_proxies: Option<Vec<ChannelPrefix>>,

    /// Route categories available across all listeners
    pub routes: HashMap<String, RouteCategory>,

    /// OAuth callback route prefix (e.g. "/oauth/callback")
    /// Defaults to "/v1/identity/oauth/callback" if not set
    #[serde(default = "default_oauth_callback_route")]
    pub oauth_callback_route: String,

    /// Logging overrides (only redaction rules are used from gateway.json;
    /// level/json/log_directory come from config.toml)
    #[serde(default)]
    pub logging: Option<crate::config::LoggingConfig>,

    /// STS (`/oauth2/token`) runtime controls (replay-protection backend, throttle).
    #[serde(default)]
    pub sts: crate::config::types::StsRuntimeConfig,

    /// Per-source-address limit on each `fabric` CLI login endpoint.
    #[serde(default)]
    pub cli_login_throttle: crate::config::types::LoginThrottleConfig,
}

/// DID configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DidConfig {
    /// Domain used for did:web generation
    pub domain: String,
}

/// WebAuthn configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebAuthnConfig {
    /// Relying Party ID (typically the domain)
    pub rp_id: String,

    /// External origin URL (for WebAuthn when behind proxy)
    pub external_origin: String,
}

fn default_listener_type_inbound() -> String {
    "inbound".to_string()
}

fn default_oauth_callback_route() -> String {
    "/v1/identity/oauth/callback".to_string()
}

/// A single port listener configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Listener {
    /// Unique identifier for this listener
    pub id: String,

    /// Human-readable name
    pub name: String,

    /// Bind address (typically "0.0.0.0")
    pub bind_address: String,

    /// Port to bind to
    pub port: u16,

    /// Protocol: "http" or "https"
    pub protocol: String,

    /// External URLs that route to this listener (e.g., ngrok URLs)
    pub external_urls: Vec<String>,

    /// Listener direction: `"inbound"` (default) or `"outbound"`.
    /// Existing configs that omit this field default to `"inbound"`.
    #[serde(default = "default_listener_type_inbound")]
    pub listener_type: String,
}

/// A channel prefix configuration for proxy routes
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelPrefix {
    /// Unique identifier for this channel prefix
    pub id: String,

    /// Human-readable name (displayed in UI dropdown)
    pub name: String,

    /// Route prefix (e.g., "/channels", "/cats")
    pub prefix: String,
}

/// Type of route handler
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum RouteType {
    /// Proxy requests to backend channels
    Proxy,
    /// Serve the Identity API endpoints
    IdentityApi,
    /// Serve static files from a directory
    Static,
    /// Serve connection point DID documents
    ConnectionPoint,
    /// Redirect to another path
    Redirect,
    /// Serve onboarding endpoints
    Onboarding,
}

/// A category of routes (e.g., "channels", "agents", "routes")
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteCategory {
    /// Type of route handler
    #[serde(rename = "type")]
    pub route_type: RouteType,

    /// Prefix for this category (e.g., "/channels")
    pub prefix: String,

    /// For static routes: filesystem path to serve
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,

    /// For redirect routes: target URL to redirect to
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,

    /// For static routes: whether this should be the fallback handler
    #[serde(default)]
    pub fallback: bool,
}

impl NetworkConfig {
    /// Load network configuration from a JSON file
    pub fn load_from_file(path: &str) -> anyhow::Result<Self> {
        let contents = std::fs::read_to_string(path)?;
        let mut config: NetworkConfig = serde_json::from_str(&contents)?;
        for category in config
            .integration
            .add_missing_built_in_categories()
        {
            tracing::warn!(
                category,
                path,
                "gateway.json has no '{category}' integration category; offering the built-in one. Add it to integration.categories to customise it"
            );
        }
        config.validate_listeners()?;
        config.validate_terms()?;
        if let Some(profile) = &config.sts.mcp_issuer {
            profile.validate_network(&config)?;
            config
                .sts
                .mcp_replay
                .validate()?;
        }
        Ok(config)
    }

    /// Reject configurations that would race the OS for the same socket or
    /// produce ambiguous id-based lookups. Two listeners on the same
    /// `bind_address:port` can never both bind, and duplicate `id` values
    /// silently shadow each other in routing tables — we surface both at
    /// startup rather than letting the second `bind()` fail mid-boot.
    fn validate_listeners(&self) -> anyhow::Result<()> {
        validate_listener_set(&self.listeners)
    }

    fn validate_terms(&self) -> anyhow::Result<()> {
        if !self.terms {
            return Ok(());
        }
        let url = self
            .affinidi_terms_url
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("affinidi_terms_url is required when terms are enabled"))?;
        validate_affinidi_terms_url(url, cfg!(debug_assertions))
    }

    /// Get all unique ports that should be bound
    pub fn get_ports(&self) -> Vec<u16> {
        self.listeners
            .iter()
            .map(|l| l.port)
            .collect()
    }

    /// Get listener by port
    #[allow(dead_code)]
    pub fn get_listener_by_port(
        &self,
        port: u16,
    ) -> Option<&Listener> {
        self.listeners
            .iter()
            .find(|l| l.port == port)
    }

    /// Get all external URLs across all listeners
    pub fn get_all_external_urls(&self) -> Vec<String> {
        self.listeners
            .iter()
            .flat_map(|l| {
                l.external_urls
                    .iter()
                    .cloned()
            })
            .collect()
    }

    /// Get external URLs from inbound listeners only
    pub fn get_inbound_external_urls(&self) -> Vec<String> {
        self.listeners
            .iter()
            .filter(|l| l.listener_type == "inbound")
            .flat_map(|l| {
                l.external_urls
                    .iter()
                    .cloned()
            })
            .collect()
    }

    /// Get external URLs from outbound listeners only
    pub fn get_outbound_external_urls(&self) -> Vec<String> {
        self.listeners
            .iter()
            .filter(|l| l.listener_type == "outbound")
            .flat_map(|l| {
                l.external_urls
                    .iter()
                    .cloned()
            })
            .collect()
    }

    /// Normalize localhost DID domains to a reachable inbound localhost listener.
    ///
    /// DID domains do not carry a URL scheme, so when a localhost domain points at
    /// a listener that is not externally reachable we align it with the configured
    /// inbound localhost external URL. `did:webvh` requires HTTPS, so HTTPS is
    /// preferred; HTTP is only used as a local-development fallback when no inbound
    /// HTTPS localhost external URL is configured.
    pub fn normalize_localhost_did_domain(&mut self) -> Option<(String, String)> {
        let current = self.did.domain.clone();
        let current_url = Url::parse(&format!("http://{}", current)).ok()?;
        if current_url.host_str() != Some("localhost") {
            return None;
        }

        let replacement = ["https", "http"]
            .into_iter()
            .find_map(|scheme| {
                self.listeners
                    .iter()
                    .filter(|listener| listener.listener_type == "inbound")
                    .flat_map(|listener| listener.external_urls.iter())
                    .filter_map(|external_url| Url::parse(external_url).ok())
                    .find(|url| {
                        url.scheme()
                            .eq_ignore_ascii_case(scheme)
                            && url.host_str() == Some("localhost")
                    })
                    .map(|url| match url.port() {
                        Some(port) => format!("localhost:{port}"),
                        None => "localhost".to_string(),
                    })
            })?;

        if replacement == current {
            return None;
        }

        self.did.domain = replacement.clone();
        Some((current, replacement))
    }

    /// Get the ports of every outbound listener. Used to bucket outbound
    /// virtual channels: a VC whose effective `listen_address` resolves to
    /// a non-outbound port gets logged as misconfigured rather than
    /// silently dropped onto an inbound listener that won't serve it.
    pub fn get_outbound_ports(&self) -> Vec<u16> {
        self.listeners
            .iter()
            .filter(|l| l.listener_type == "outbound")
            .map(|l| l.port)
            .collect()
    }

    /// Get all route prefixes from the top-level routes
    #[allow(dead_code)]
    pub fn get_all_route_prefixes(&self) -> Vec<String> {
        self.routes
            .keys()
            .cloned()
            .collect()
    }

    /// Get channel prefixes (for UI dropdown)
    #[allow(dead_code)]
    pub fn get_channel_prefixes(&self) -> Vec<String> {
        self.channels
            .iter()
            .map(|c| c.prefix.clone())
            .collect()
    }

    /// Get channel prefix configurations (for UI dropdown with names)
    pub fn get_channel_prefix_configs(&self) -> &Vec<ChannelPrefix> {
        &self.channels
    }

    /// Map an external URL to its internal port
    pub fn map_url_to_port(
        &self,
        url: &str,
    ) -> Option<u16> {
        self.map_url_to_port_for_type(url, None)
    }

    /// Map an external URL to its internal port, restricted to listeners of
    /// the given type. When `preferred_type` is `None`, any listener match is
    /// returned. When `preferred_type` is `Some`, only listeners whose
    /// `listener_type` equals the preference are considered — never falls back
    /// to a listener of a different type, because callers asking for a
    /// specific kind (e.g. `"outbound"`) would otherwise receive (and later
    /// abort) the inbound listener that happens to share the URL.
    pub fn map_url_to_port_for_type(
        &self,
        url: &str,
        preferred_type: Option<&str>,
    ) -> Option<u16> {
        let normalized_url = url
            .trim_start_matches("https://")
            .trim_start_matches("http://");

        for listener in &self.listeners {
            if let Some(t) = preferred_type
                && listener.listener_type != t
            {
                continue;
            }
            for ext_url in &listener.external_urls {
                let normalized_ext = ext_url
                    .trim_start_matches("https://")
                    .trim_start_matches("http://");

                if normalized_ext == normalized_url || ext_url == url {
                    return Some(listener.port);
                }
            }
        }

        None
    }
}

fn validate_listener_set(listeners: &[Listener]) -> anyhow::Result<()> {
    use std::collections::HashSet;

    let mut ids: HashSet<&str> = HashSet::new();
    for l in listeners {
        if !ids.insert(l.id.as_str()) {
            anyhow::bail!("Invalid network config: duplicate listener id '{}'", l.id);
        }
    }

    let mut sockets: HashSet<(&str, u16)> = HashSet::new();
    for l in listeners {
        if !sockets.insert((l.bind_address.as_str(), l.port)) {
            anyhow::bail!(
                "Invalid network config: duplicate listener bind address {}:{} (listener id '{}')",
                l.bind_address,
                l.port,
                l.id
            );
        }
    }

    Ok(())
}

#[cfg(test)]
mod listener_validation_tests {
    use super::*;

    fn listener(
        id: &str,
        bind: &str,
        port: u16,
    ) -> Listener {
        Listener {
            id: id.to_string(),
            name: id.to_string(),
            bind_address: bind.to_string(),
            port,
            protocol: "http".to_string(),
            external_urls: vec![],
            listener_type: "inbound".to_string(),
        }
    }

    #[test]
    fn duplicate_port_is_rejected() {
        let err = validate_listener_set(&[listener("a", "0.0.0.0", 8080), listener("b", "0.0.0.0", 8080)])
            .unwrap_err()
            .to_string();
        assert!(err.contains("duplicate listener bind address 0.0.0.0:8080"), "got: {err}");
    }

    #[test]
    fn duplicate_id_is_rejected() {
        let err = validate_listener_set(&[listener("same", "0.0.0.0", 8080), listener("same", "0.0.0.0", 9090)])
            .unwrap_err()
            .to_string();
        assert!(err.contains("duplicate listener id 'same'"), "got: {err}");
    }

    #[test]
    fn distinct_ports_and_ids_pass() {
        validate_listener_set(&[listener("a", "0.0.0.0", 8080), listener("b", "0.0.0.0", 9090)]).unwrap();
    }

    #[test]
    fn same_port_on_different_bind_addresses_passes() {
        validate_listener_set(&[listener("a", "127.0.0.1", 8080), listener("b", "10.0.0.1", 8080)]).unwrap();
    }
}

fn validate_affinidi_terms_url(
    url: &Url,
    allow_loopback_http: bool,
) -> anyhow::Result<()> {
    let loopback_http = allow_loopback_http
        && url.scheme() == "http"
        && url
            .host()
            .is_some_and(|host| match host {
                url::Host::Domain(host) => host == "localhost",
                url::Host::Ipv4(address) => address.is_loopback(),
                url::Host::Ipv6(address) => address.is_loopback(),
            });
    if (url.scheme() != "https" && !loopback_http)
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
    {
        anyhow::bail!("affinidi_terms_url must be an absolute HTTPS URL without credentials");
    }
    Ok(())
}

#[cfg(test)]
mod url_mapping_tests {
    use super::*;

    fn cfg_with_listeners(listeners_json: serde_json::Value) -> NetworkConfig {
        let cfg = serde_json::json!({
            "did": { "domain": "test.local" },
            "webauthn": { "rp_id": "localhost", "external_origin": "https://localhost" },
            "integration": { "types": [], "categories": [] },
            "listeners": listeners_json,
            "routes": {},
        });
        serde_json::from_value(cfg).expect("test network config should deserialize")
    }

    #[test]
    fn terms_defaults_to_disabled() {
        assert!(!cfg_with_listeners(serde_json::json!([])).terms);
    }

    #[test]
    fn local_testing_allows_a_loopback_http_metadata_url() {
        let url = Url::parse("http://127.0.0.1:8080/terms").unwrap();

        validate_affinidi_terms_url(&url, true).unwrap();
    }

    #[test]
    fn production_terms_reject_a_loopback_http_metadata_url() {
        let url = Url::parse("http://127.0.0.1:8080/terms").unwrap();

        let error = validate_affinidi_terms_url(&url, false)
            .unwrap_err()
            .to_string();

        assert!(error.contains("absolute HTTPS URL"), "got: {error}");
    }

    #[test]
    fn enabled_terms_require_an_affinidi_metadata_url() {
        let mut config = cfg_with_listeners(serde_json::json!([]));
        config.terms = true;

        let error = config
            .validate_terms()
            .unwrap_err()
            .to_string();

        assert!(error.contains("affinidi_terms_url"), "got: {error}");
    }

    /// Regression: a surface with `outbound_listen_address` matching an
    /// **inbound** listener's URL must NOT map to that inbound port when
    /// the caller asks specifically for an outbound listener. Otherwise
    /// the dynamic outbound-rebuild path will abort the inbound listener
    /// (dashboard + channel proxies go dark after save).
    #[test]
    fn preferred_outbound_does_not_fall_back_to_inbound() {
        let cfg = cfg_with_listeners(serde_json::json!([
            {
                "id": "dashboard",
                "name": "dashboard",
                "bind_address": "0.0.0.0",
                "port": 8443,
                "protocol": "https",
                "external_urls": ["https://gw.example.com"],
                "listener_type": "inbound"
            }
        ]));

        assert_eq!(cfg.map_url_to_port_for_type("https://gw.example.com", Some("outbound")), None);
        assert_eq!(cfg.map_url_to_port_for_type("https://gw.example.com", Some("inbound")), Some(8443));
        assert_eq!(cfg.map_url_to_port("https://gw.example.com"), Some(8443));
    }

    #[test]
    fn preferred_outbound_picks_outbound_when_both_share_url() {
        let cfg = cfg_with_listeners(serde_json::json!([
            {
                "id": "in", "name": "in", "bind_address": "0.0.0.0", "port": 8443,
                "protocol": "https", "external_urls": ["https://gw.example.com"], "listener_type": "inbound"
            },
            {
                "id": "out", "name": "out", "bind_address": "0.0.0.0", "port": 9443,
                "protocol": "https", "external_urls": ["https://gw.example.com"], "listener_type": "outbound"
            }
        ]));

        assert_eq!(cfg.map_url_to_port_for_type("https://gw.example.com", Some("outbound")), Some(9443));
        assert_eq!(cfg.map_url_to_port_for_type("https://gw.example.com", Some("inbound")), Some(8443));
    }

    #[test]
    fn unspecified_preference_returns_any_match() {
        let cfg = cfg_with_listeners(serde_json::json!([
            {
                "id": "out", "name": "out", "bind_address": "0.0.0.0", "port": 9443,
                "protocol": "https", "external_urls": ["https://gw.example.com"], "listener_type": "outbound"
            }
        ]));
        assert_eq!(cfg.map_url_to_port("https://gw.example.com"), Some(9443));
    }

    #[test]
    fn normalize_localhost_did_domain_prefers_https_listener() {
        let mut cfg = cfg_with_listeners(serde_json::json!([
            {
                "id": "http", "name": "http", "bind_address": "0.0.0.0", "port": 8080,
                "protocol": "http", "external_urls": ["http://localhost:8080"], "listener_type": "inbound"
            },
            {
                "id": "https", "name": "https", "bind_address": "0.0.0.0", "port": 8443,
                "protocol": "https", "external_urls": ["https://localhost:8443"], "listener_type": "inbound"
            }
        ]));
        cfg.did.domain = "localhost:8080".to_string();

        let change = cfg.normalize_localhost_did_domain();

        assert_eq!(change, Some(("localhost:8080".to_string(), "localhost:8443".to_string())));
        assert_eq!(cfg.did.domain, "localhost:8443");
    }

    #[test]
    fn normalize_localhost_did_domain_falls_back_to_http_listener() {
        let mut cfg = cfg_with_listeners(serde_json::json!([
            {
                "id": "http", "name": "http", "bind_address": "0.0.0.0", "port": 8080,
                "protocol": "http", "external_urls": ["http://localhost:8080"], "listener_type": "inbound"
            }
        ]));
        cfg.did.domain = "localhost:8443".to_string();

        let change = cfg.normalize_localhost_did_domain();

        assert_eq!(change, Some(("localhost:8443".to_string(), "localhost:8080".to_string())));
        assert_eq!(cfg.did.domain, "localhost:8080");
    }

    #[test]
    fn normalize_localhost_did_domain_noops_for_non_localhost() {
        let mut cfg = cfg_with_listeners(serde_json::json!([
            {
                "id": "http", "name": "http", "bind_address": "0.0.0.0", "port": 8080,
                "protocol": "http", "external_urls": ["http://localhost:8080"], "listener_type": "inbound"
            }
        ]));
        cfg.did.domain = "gateway.example.com".to_string();

        assert_eq!(cfg.normalize_localhost_did_domain(), None);
        assert_eq!(cfg.did.domain, "gateway.example.com");
    }

    #[test]
    fn mcp_proxies_deserialize_from_top_level_field() {
        let cfg: NetworkConfig = serde_json::from_value(serde_json::json!({
            "did": { "domain": "test.local" },
            "webauthn": { "rp_id": "localhost", "external_origin": "https://localhost" },
            "integration": { "types": [], "categories": [] },
            "listeners": [],
            "routes": {},
            "mcp_proxies": [
                { "id": "mcp", "name": "mcp", "prefix": "/mcp" },
                { "id": "tools", "name": "tools", "prefix": "/tools" }
            ],
        }))
        .expect("network config with top-level mcp_proxies should deserialize");

        let prefixes = cfg
            .mcp_proxies
            .expect("mcp_proxies should be present");
        assert_eq!(prefixes.len(), 2);
        assert_eq!(prefixes[0].id, "mcp");
        assert_eq!(prefixes[0].prefix, "/mcp");
        assert_eq!(prefixes[1].id, "tools");
        assert_eq!(prefixes[1].prefix, "/tools");
    }

    #[test]
    fn mcp_proxies_absent_deserializes_to_none() {
        let cfg: NetworkConfig = serde_json::from_value(serde_json::json!({
            "did": { "domain": "test.local" },
            "webauthn": { "rp_id": "localhost", "external_origin": "https://localhost" },
            "integration": { "types": [], "categories": [] },
            "listeners": [],
            "routes": {},
        }))
        .expect("network config without mcp_proxies should deserialize");

        assert!(cfg.mcp_proxies.is_none());
    }
}
