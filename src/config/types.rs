//! Type definitions for configuration

use crate::config::EncryptionConfig;

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Default Affinidi agent identity extension URI
pub const AFFINIDI_AGENT_IDENTITY_EXTENSION: &str = "https://fabric.affinidi.io/extensions/agent-identity/v1";
pub const AFFINIDI_AGENT_METADATA_EXTENSION: &str = "https://fabric.affinidi.io/extensions/custom-metadata/v1";
/// Agent identity credential extension - contains VP with VC signed by agent DID
pub const AFFINIDI_AGENT_IDENTITY_CREDENTIAL_EXTENSION: &str =
    "https://fabric.affinidi.io/extensions/agent-identity-credential/v1";
/// Agent identity binding extension - VP proving caller+agent binding, injected on request path
pub const AFFINIDI_AGENT_IDENTITY_BINDING_EXTENSION: &str =
    "https://fabric.affinidi.io/extensions/agent-identity-binding/v1";
/// Trust Registry extension - contains trust registry verification parameters
pub const TRUST_REGISTRY_EXTENSION: &str = "https://fabric.affinidi.io/extensions/trust-registry";

pub const MCP_AGENT_IDENTITY_KEY: &str = "io.affinidi.fabric/agent-identity";
pub const MCP_CUSTOM_METADATA_KEY: &str = "io.affinidi.fabric/custom-metadata";
pub const MCP_AGENT_IDENTITY_CREDENTIAL_KEY: &str = "io.affinidi.fabric/agent-identity-credential";
pub const MCP_AGENT_IDENTITY_BINDING_KEY: &str = "io.affinidi.fabric/agent-identity-binding";
pub const MCP_TRUST_REGISTRY_KEY: &str = "io.affinidi.fabric/trust-registry";

pub const MCP_METADATA_ALIASES: &[(&str, &str)] = &[
    (AFFINIDI_AGENT_IDENTITY_EXTENSION, MCP_AGENT_IDENTITY_KEY),
    (AFFINIDI_AGENT_METADATA_EXTENSION, MCP_CUSTOM_METADATA_KEY),
    (AFFINIDI_AGENT_IDENTITY_CREDENTIAL_EXTENSION, MCP_AGENT_IDENTITY_CREDENTIAL_KEY),
    (AFFINIDI_AGENT_IDENTITY_BINDING_EXTENSION, MCP_AGENT_IDENTITY_BINDING_KEY),
    (TRUST_REGISTRY_EXTENSION, MCP_TRUST_REGISTRY_KEY),
];

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum McpLegacyMetadataOutput {
    #[default]
    Compatibility,
    Canonical,
}

/// Accepts a retired setting that stored records and API payloads may still
/// carry, so they keep loading under `deny_unknown_fields`. Any value is
/// discarded, and a field of this type must be `skip_serializing`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RetiredSetting;

impl<'de> Deserialize<'de> for RetiredSetting {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        serde::de::IgnoredAny::deserialize(deserializer).map(|_| Self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct McpHttpConfig {
    pub allowed_origins: Vec<String>,
    pub max_request_bytes: std::num::NonZeroUsize,
    pub max_header_bytes: std::num::NonZeroUsize,
    pub max_accept_ranges: std::num::NonZeroUsize,
    pub max_response_bytes: std::num::NonZeroUsize,
    pub max_chunk_bytes: std::num::NonZeroUsize,
    pub stream_idle_timeout_secs: std::num::NonZeroU64,
    pub stream_max_lifetime_secs: std::num::NonZeroU64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorization: Option<crate::mcp::resource_server::McpResourceServerConfig>,
}

impl Default for McpHttpConfig {
    fn default() -> Self {
        Self {
            allowed_origins: Vec::new(),
            max_request_bytes: std::num::NonZeroUsize::new(1024 * 1024).unwrap(),
            max_header_bytes: std::num::NonZeroUsize::new(16 * 1024).unwrap(),
            max_accept_ranges: std::num::NonZeroUsize::new(32).unwrap(),
            max_response_bytes: std::num::NonZeroUsize::new(1024 * 1024).unwrap(),
            max_chunk_bytes: std::num::NonZeroUsize::new(256 * 1024).unwrap(),
            stream_idle_timeout_secs: std::num::NonZeroU64::new(60).unwrap(),
            stream_max_lifetime_secs: std::num::NonZeroU64::new(3600).unwrap(),
            authorization: None,
        }
    }
}

impl McpHttpConfig {
    pub fn validate(&self) -> Result<(), String> {
        crate::mcp::modern_http::OriginPolicy::new(&[], &self.allowed_origins)?;
        if let Some(authorization) = &self.authorization {
            authorization.validate()?;
        }
        if self.stream_idle_timeout_secs > self.stream_max_lifetime_secs
            || self
                .stream_max_lifetime_secs
                .get()
                > 86400
        {
            return Err("MCP stream timeouts require idle <= maximum lifetime <= 86400 seconds".to_string());
        }
        Ok(())
    }
}

fn default_true() -> bool {
    true
}

/// integration type definition with metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrationType {
    /// Unique identifier for this integration type (e.g., "email", "slack")
    pub enum_value: String,

    /// Human-readable name
    pub name: String,

    /// Description of this integration type
    pub description: String,

    /// Metadata specific to this integration type (field definitions, etc.)
    #[serde(default)]
    pub metadata: serde_json::Value,
}

/// integration category definition with metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrationCategory {
    /// Unique identifier for this category (e.g., "general", "connection_point")
    #[serde(deserialize_with = "deserialize_integration_category_value")]
    pub enum_value: String,

    /// Human-readable name
    pub name: String,

    /// Description of this category
    pub description: String,

    /// Metadata specific to this category
    #[serde(default)]
    pub metadata: serde_json::Value,
}

/// The `channel` integration category was renamed to `surface`; a
/// `gateway.json` written before the rename still carries the old value.
fn deserialize_integration_category_value<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = String::deserialize(deserializer)?;
    Ok(if value == "channel" {
        "surface".to_string()
    } else {
        value
    })
}

/// integration configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrationConfig {
    /// Regex pattern for matching template variables in ${VARIABLE} or ${VARIABLE:Label} format
    #[serde(default = "default_variable_pattern")]
    pub variable_pattern: String,

    /// Description of the variable pattern
    #[serde(default)]
    pub variable_pattern_description: Option<String>,

    /// Prefix for custom variables (default: "_")
    #[serde(default = "default_custom_variable_prefix")]
    pub custom_variable_prefix: String,

    /// Valid integration types with metadata
    pub types: Vec<IntegrationType>,

    /// Valid integration categories with metadata
    pub categories: Vec<IntegrationCategory>,
}

fn default_variable_pattern() -> String {
    r"\$\{([^:}]+)(?::([^}]+))?\}".to_string()
}

fn default_custom_variable_prefix() -> String {
    "_".to_string()
}

/// Built-in integration categories a `gateway.json` written before they
/// shipped still lacks. They are added at load so an upgrade offers them
/// without an edit; other categories stay as the operator configured them.
const CATEGORIES_ADDED_ON_LOAD: [&str; 1] = ["audit"];

impl IntegrationConfig {
    /// Add each [`CATEGORIES_ADDED_ON_LOAD`] category the configuration lacks,
    /// taken from [`Self::default_config`]. Returns the categories added.
    pub fn add_missing_built_in_categories(&mut self) -> Vec<String> {
        let built_in = Self::default_config().categories;
        let mut added = Vec::new();
        for value in CATEGORIES_ADDED_ON_LOAD {
            if self
                .categories
                .iter()
                .any(|c| c.enum_value == value)
            {
                continue;
            }
            if let Some(category) = built_in
                .iter()
                .find(|c| c.enum_value == value)
            {
                self.categories
                    .push(category.clone());
                added.push(value.to_string());
            }
        }
        added
    }

    /// Create a default integration configuration with standard types and categories
    /// This is used as a fallback when constructing configs programmatically
    pub fn default_config() -> Self {
        Self {
            variable_pattern: default_variable_pattern(),
            variable_pattern_description: Some("Matches ${VARIABLE} or ${VARIABLE:Label} format. Variable name can contain any characters except : and }".to_string()),
            custom_variable_prefix: default_custom_variable_prefix(),
            types: vec![
                IntegrationType {
                    enum_value: "email".to_string(),
                    name: "Email".to_string(),
                    description: "Send notifications via SMTP email".to_string(),
                    metadata: serde_json::json!({
                        "fields": [
                            {"name": "subject", "label": "Subject", "type": "string", "required": true},
                            {"name": "body", "label": "Body", "type": "text", "required": true},
                            {"name": "from_address", "label": "From Address", "type": "string", "required": true},
                            {"name": "to_addresses", "label": "To Addresses", "type": "string", "required": true},
                            {"name": "smtp_host", "label": "SMTP Host", "type": "string", "required": true},
                            {"name": "smtp_port", "label": "SMTP Port", "type": "number", "required": true},
                            {"name": "smtp_username", "label": "SMTP Username", "type": "string", "required": false},
                            {"name": "smtp_password", "label": "SMTP Password", "type": "password", "required": false}
                        ]
                    }),
                },
                IntegrationType {
                    enum_value: "slack".to_string(),
                    name: "Slack".to_string(),
                    description: "Send notifications to Slack channels via webhook".to_string(),
                    metadata: serde_json::json!({
                        "fields": [
                            {"name": "webhook_url", "label": "Webhook URL", "type": "string", "required": true},
                            {"name": "message", "label": "Message", "type": "text", "required": true},
                            {"name": "channel", "label": "Channel", "type": "string", "required": false}
                        ]
                    }),
                },
                IntegrationType {
                    enum_value: "webhook".to_string(),
                    name: "Webhook".to_string(),
                    description: "Send HTTP POST requests to custom endpoints".to_string(),
                    metadata: serde_json::json!({
                        "fields": [
                            {"name": "url", "label": "Webhook URL", "type": "string", "required": true},
                            {"name": "payload", "label": "Payload Template", "type": "text", "required": true},
                            {"name": "headers", "label": "Custom Headers (JSON)", "type": "text", "required": false}
                        ]
                    }),
                },
                IntegrationType {
                    enum_value: "stream".to_string(),
                    name: "Stream".to_string(),
                    description: "Stream events to Kafka, Kinesis, Pulsar, or Redis Streams".to_string(),
                    metadata: serde_json::json!({
                        "fields": [
                            {"name": "phone_number", "label": "To Phone Number", "type": "string", "required": true},
                            {"name": "message", "label": "Message", "type": "text", "required": true},
                            {"name": "from_number", "label": "From Number", "type": "string", "required": true},
                            {"name": "provider_api_key", "label": "Provider API Key", "type": "password", "required": true}
                        ]
                    }),
                },
            ],
            categories: vec![
                IntegrationCategory {
                    enum_value: "general".to_string(),
                    name: "General".to_string(),
                    description: "General purpose notifications".to_string(),
                    metadata: serde_json::json!({}),
                },
                IntegrationCategory {
                    enum_value: "connection_point".to_string(),
                    name: "Connection Point".to_string(),
                    description: "Notifications related to connection point events".to_string(),
                    metadata: serde_json::json!({}),
                },
                IntegrationCategory {
                    enum_value: "user".to_string(),
                    name: "User".to_string(),
                    description: "User-specific notifications".to_string(),
                    metadata: serde_json::json!({}),
                },
                IntegrationCategory {
                    enum_value: "gateway".to_string(),
                    name: "Gateway".to_string(),
                    description: "Gateway system notifications".to_string(),
                    metadata: serde_json::json!({}),
                },
                IntegrationCategory {
                    enum_value: "surface".to_string(),
                    name: "Surface".to_string(),
                    description: "Agent Surface notifications".to_string(),
                    metadata: serde_json::json!({}),
                },
                IntegrationCategory {
                    enum_value: "x402".to_string(),
                    name: "X402 Payments".to_string(),
                    description: "X402 payment transaction and monitoring notifications (transaction failures, settlement errors)".to_string(),
                    metadata: serde_json::json!({
                        "event_types": [
                            {"event": "x402.verification.failed", "description": "Payment verification failed"},
                            {"event": "x402.settlement.failed", "description": "Payment settlement failed"},
                            {"event": "x402.transaction.completed", "description": "Payment transaction completed successfully"},
                            {"event": "x402.cleanup.completed", "description": "Transaction cleanup completed"}
                        ]
                    }),
                },
                crate::integrations::audit_integration_triggers::audit_integration_category(),
            ],
        }
    }
}

/// OOB (Out-of-Band) connection configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OobConnectionConfig {
    /// How long (in hours) a pending OOB connection request remains valid
    /// After this time, the temporary listener will be stopped and cleaned up
    #[serde(default = "default_pending_expiry_hours")]
    pub pending_expiry_hours: u64,
}

impl Default for OobConnectionConfig {
    fn default() -> Self {
        Self {
            pending_expiry_hours: default_pending_expiry_hours(),
        }
    }
}

fn default_pending_expiry_hours() -> u64 {
    1
}

/// Reconnect policy for connection-point DIDComm links (proposal section C).
///
/// A failed connection is retried with exponential backoff up to
/// `max_backoff_seconds`, after which it retries at that fixed interval
/// (e.g. 30s → 60s → … → 1800s, then every 1800s).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReconnectPolicyConfig {
    /// Initial backoff after the first failed attempt.
    #[serde(default = "default_reconnect_initial_backoff_seconds")]
    pub initial_backoff_seconds: u64,

    /// Cap on the backoff; also the fixed cadence once the cap is reached.
    #[serde(default = "default_reconnect_max_backoff_seconds")]
    pub max_backoff_seconds: u64,

    /// Multiplier applied to the backoff after each failure. `<= 1.0` disables
    /// growth (constant `initial_backoff_seconds`).
    #[serde(default = "default_reconnect_backoff_multiplier")]
    pub backoff_multiplier: f64,
}

impl Default for ReconnectPolicyConfig {
    fn default() -> Self {
        Self {
            initial_backoff_seconds: default_reconnect_initial_backoff_seconds(),
            max_backoff_seconds: default_reconnect_max_backoff_seconds(),
            backoff_multiplier: default_reconnect_backoff_multiplier(),
        }
    }
}

impl ReconnectPolicyConfig {
    /// Convert to the runtime [`crate::comm::connection_health::ReconnectPolicy`].
    pub fn to_policy(&self) -> crate::comm::connection_health::ReconnectPolicy {
        crate::comm::connection_health::ReconnectPolicy {
            initial_backoff_seconds: self.initial_backoff_seconds,
            max_backoff_seconds: self.max_backoff_seconds,
            backoff_multiplier: self.backoff_multiplier,
        }
    }
}

fn default_reconnect_initial_backoff_seconds() -> u64 {
    30
}

fn default_reconnect_max_backoff_seconds() -> u64 {
    1800
}

fn default_reconnect_backoff_multiplier() -> f64 {
    2.0
}

/// TLS certificate configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsConfig {
    /// Path to the TLS certificate file (PEM format)
    pub cert_path: PathBuf,

    /// Path to the TLS private key file (PEM format)
    pub key_path: PathBuf,

    /// Whether to verify upstream TLS certificates
    #[serde(default = "default_true")]
    pub verify_upstream: bool,

    /// Inbound client authentication configuration (mTLS).
    ///
    /// Controls whether the gateway requests/requires client certificates
    /// during the TLS handshake and/or trusts forwarded client certs from
    /// upstream proxies. See [`ClientAuthConfig`].
    ///
    /// Default = disabled — no behavioural change for existing deployments.
    #[serde(default)]
    pub client_auth: ClientAuthConfig,
}

/// Inbound client-certificate authentication configuration.
///
/// Two independent capture paths:
///
/// 1. **Direct TLS termination** ([`Self::direct`]): the gateway itself asks
///    for a client certificate during the TLS handshake via rustls'
///    `WebPkiClientVerifier`.
/// 2. **Forwarded client cert** ([`Self::trusted_proxies`] + [`Self::forwarded_header`]):
///    an upstream L7 LB terminates TLS and forwards the client cert in a
///    header. Only honoured when the connecting peer IP matches a trusted
///    proxy CIDR.
///
/// Either or both may be enabled. Per-channel `MtlsAuthConfig` decides
/// whether forwarded certs are acceptable on that channel.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ClientAuthConfig {
    /// Direct-TLS client-cert handshake mode.
    #[serde(default)]
    pub direct: DirectClientAuthMode,

    /// Trusted proxy CIDRs allowed to provide forwarded client certs.
    /// Empty disables the forwarded path.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub trusted_proxies: Vec<ipnet::IpNet>,

    /// Forwarded-client-cert header configuration. Ignored when
    /// `trusted_proxies` is empty.
    #[serde(default)]
    pub forwarded_header: ForwardedHeaderConfig,
}

/// Whether the TLS handshake requests/requires client certificates.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DirectClientAuthMode {
    /// Don't request a client cert during the TLS handshake. (Default.)
    #[default]
    Disabled,
    /// Request a client cert; accept connections with or without one.
    /// Channels with `Mtls` source auth still reject missing certs at the
    /// middleware layer.
    Optional,
    /// Require a client cert at handshake time. TLS handshake fails for
    /// connections that don't present one. Only safe on listeners where
    /// every channel uses mTLS.
    Required,
}

/// Format of the inbound forwarded-client-cert header.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForwardedHeaderConfig {
    /// Header name to read.
    #[serde(default = "default_forwarded_header_name")]
    pub header_name: String,

    /// Header value format.
    #[serde(default)]
    pub format: ForwardedHeaderFormat,
}

impl Default for ForwardedHeaderConfig {
    fn default() -> Self {
        Self {
            header_name: default_forwarded_header_name(),
            format: ForwardedHeaderFormat::default(),
        }
    }
}

/// Wire format of the forwarded-client-cert header.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ForwardedHeaderFormat {
    /// Envoy XFCC grammar:
    /// `By=<spiffe>;Hash=<hex>;Cert="<url-enc-pem>";Chain="<url-enc-pem>";Subject="<rfc4514>";URI=<uri>;DNS=<dns>`
    #[default]
    EnvoyXfcc,
    /// nginx `ssl_client_escaped_cert`-style: URL-encoded PEM as the entire
    /// header value.
    UrlEncodedPem,
}

fn default_forwarded_header_name() -> String {
    "x-forwarded-client-cert".to_string()
}

/// A2A protocol specific configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct A2aConfig {
    /// Default A2A protocol version to use
    #[serde(default = "default_a2a_version")]
    pub default_version: String,

    /// Deprecated and ignored: message validation is set per A2A Access Point
    /// (`access_point.a2a.validate_messages`, off by default).
    ///
    /// Still accepted so an existing config file starts; a startup warning
    /// names it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub validate_messages: Option<bool>,

    /// Maximum request body size in bytes; also caps a buffered upstream
    /// response on Access Points and Transit Points.
    #[serde(default = "default_max_body_size")]
    pub max_body_size: usize,

    /// Request timeout in seconds
    #[serde(default = "default_timeout")]
    pub timeout_seconds: u64,

    /// Fabric gateway request timeout in milliseconds (for fabric:// flows)
    /// This is how long GW1 will wait for a response from GW2
    #[serde(default = "default_fabric_timeout_ms")]
    pub fabric_gateway_timeout_ms: u64,

    /// Message expiration time in seconds (TTL for DIDComm messages)
    /// Messages older than this will be dropped by the recipient.
    /// MUST be strictly greater (in ms) than `fabric_gateway_timeout_ms`,
    /// otherwise the mediator can silently drop a response while GW1 still
    /// waits for it. Enforced by [`A2aConfig::validate`].
    #[serde(default = "default_message_expires_seconds")]
    pub message_expires_seconds: u64,

    /// Maximum number of fabric request dispatches a single connection-point
    /// listener will process concurrently. A ForwardRequest that arrives while
    /// every slot is busy is answered with HTTP 503 and `retry-after: 1`; other
    /// messages wait for a free slot.
    #[serde(default = "default_max_inflight_dispatches")]
    pub max_inflight_dispatches: usize,

    /// Largest encrypted framed Fabric stream envelope this gateway sends: 64 KiB
    /// to 1 MiB and no larger than `sdk_inbound_cache_bytes`. When unset, see
    /// [`A2aConfig::stream_envelope_limit`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fabric_stream_max_envelope_bytes: Option<usize>,

    /// Maximum number of unprocessed messages the underlying DIDComm SDK
    /// inbound cache holds before it stops draining the websocket. The SDK
    /// default of 100 is too small under load; raising it prevents
    /// mediator-side back-pressure cascades.
    #[serde(default = "default_sdk_inbound_cache_count")]
    pub sdk_inbound_cache_count: u32,

    /// Maximum total bytes the SDK inbound cache holds before applying
    /// back-pressure on the websocket reader. Default 100 MiB.
    #[serde(default = "default_sdk_inbound_cache_bytes")]
    pub sdk_inbound_cache_bytes: u64,
}

impl Default for A2aConfig {
    fn default() -> Self {
        Self {
            default_version: default_a2a_version(),
            validate_messages: None,
            max_body_size: default_max_body_size(),
            timeout_seconds: default_timeout(),
            fabric_gateway_timeout_ms: default_fabric_timeout_ms(),
            message_expires_seconds: default_message_expires_seconds(),
            max_inflight_dispatches: default_max_inflight_dispatches(),
            fabric_stream_max_envelope_bytes: None,
            sdk_inbound_cache_count: default_sdk_inbound_cache_count(),
            sdk_inbound_cache_bytes: default_sdk_inbound_cache_bytes(),
        }
    }
}

impl A2aConfig {
    /// Validate runtime invariants. Called by `BootstrapConfig::validate`.
    pub fn validate(&self) -> Result<(), String> {
        // `default_version` is advertised in the cards the gateway generates, so
        // an unrecognised value would publish a version no client can act on.
        // Reject it at startup rather than serving a card that names it.
        if crate::a2a::version::supported_version(&self.default_version).is_none() {
            return Err(format!(
                "a2a.default_version '{}' is not a supported A2A protocol version (supported: {})",
                self.default_version,
                crate::a2a::version::SUPPORTED_VERSIONS.join(", ")
            ));
        }

        let expires_ms = (self.message_expires_seconds as u128).saturating_mul(1000);
        if expires_ms <= self.fabric_gateway_timeout_ms as u128 {
            return Err(format!(
                "a2a.message_expires_seconds ({}s = {}ms) must be strictly greater than \
                 a2a.fabric_gateway_timeout_ms ({}ms) — otherwise the mediator will silently \
                 drop responses while GW1 is still waiting.",
                self.message_expires_seconds, expires_ms, self.fabric_gateway_timeout_ms
            ));
        }
        if self.max_inflight_dispatches == 0 {
            return Err("a2a.max_inflight_dispatches must be > 0".to_string());
        }
        if let Some(limit) = self.fabric_stream_max_envelope_bytes
            && (!(64 * 1024..=1024 * 1024).contains(&limit) || limit as u64 > self.sdk_inbound_cache_bytes)
        {
            return Err("a2a.fabric_stream_max_envelope_bytes must be between 64 KiB and 1 MiB and fit the SDK cache"
                .to_string());
        }
        if self.sdk_inbound_cache_count == 0 {
            return Err("a2a.sdk_inbound_cache_count must be > 0".to_string());
        }
        if self.sdk_inbound_cache_bytes == 0 {
            return Err("a2a.sdk_inbound_cache_bytes must be > 0".to_string());
        }
        Ok(())
    }

    /// The configured `fabric_stream_max_envelope_bytes`, or 128 KiB capped at
    /// `sdk_inbound_cache_bytes` when unset. The derived value is not range
    /// checked, so a config without the setting validates whatever its cache size.
    pub fn stream_envelope_limit(&self) -> usize {
        const DEFAULT_LIMIT: usize = 128 * 1024;
        self.fabric_stream_max_envelope_bytes
            .unwrap_or_else(|| {
                usize::try_from(self.sdk_inbound_cache_bytes).map_or(DEFAULT_LIMIT, |cache| cache.min(DEFAULT_LIMIT))
            })
    }
}

/// MCP (Model Context Protocol) specific configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpConfig {
    /// Default MCP protocol version to use
    #[serde(default = "default_mcp_version")]
    pub default_version: String,

    /// Whether to validate MCP protocol messages
    #[serde(default = "default_true")]
    pub validate_messages: bool,

    /// Maximum tool execution timeout in seconds
    #[serde(default = "default_tool_timeout")]
    pub tool_timeout_seconds: u64,

    /// Resource cache TTL in seconds
    #[serde(default = "default_resource_cache_ttl")]
    pub resource_cache_ttl: u64,

    /// Enable SSE (Server-Sent Events) transport
    #[serde(default = "default_true")]
    pub enable_sse: bool,

    /// Enable stdio transport
    #[serde(default)]
    pub enable_stdio: bool,

    /// Fabric gateway request timeout in milliseconds (for mcp:// flows)
    #[serde(default = "default_fabric_timeout_ms")]
    pub fabric_gateway_timeout_ms: u64,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub continuations: Option<crate::mcp::continuations::config::ContinuationConfig>,
}

impl Default for McpConfig {
    fn default() -> Self {
        Self {
            default_version: default_mcp_version(),
            validate_messages: true,
            tool_timeout_seconds: default_tool_timeout(),
            resource_cache_ttl: default_resource_cache_ttl(),
            enable_sse: true,
            enable_stdio: false,
            fabric_gateway_timeout_ms: default_fabric_timeout_ms(),
            continuations: None,
        }
    }
}

/// A single log redaction rule: a regex pattern and its replacement string.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogRedactionRule {
    /// Human-readable label for this rule (e.g. "JWT tokens")
    #[serde(default)]
    pub name: String,

    /// Regex pattern to match (case-insensitive by default)
    pub pattern: String,

    /// Replacement string (may contain capture group references like $1)
    pub replacement: String,
}

/// Log redaction configuration — loaded from gateway.json `logging.redaction`.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct LogRedactionConfig {
    /// Master switch — when false, no redaction is performed
    #[serde(default)]
    pub enabled: bool,

    /// Ordered list of regex→replacement rules applied to every log line
    #[serde(default)]
    pub rules: Vec<LogRedactionRule>,
}

/// Logging configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    /// Log level (trace, debug, info, warn, error)
    #[serde(default = "default_log_level")]
    pub level: String,

    /// Whether to output logs in JSON format
    #[serde(default)]
    pub json: bool,

    /// Directory to write log files (optional, logs to stdout if not set)
    pub log_directory: Option<String>,

    /// PII / secret redaction rules applied to all log output
    #[serde(default)]
    pub redaction: LogRedactionConfig,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: default_log_level(),
            json: false,
            log_directory: None,
            redaction: LogRedactionConfig::default(),
        }
    }
}

/// Extension inspection configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtensionInspectionConfig {
    /// Whether extension inspection is enabled
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// List of extension URIs to watch for and display
    #[serde(default)]
    pub watch_extensions: Vec<String>,
}

impl Default for ExtensionInspectionConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            watch_extensions: vec![],
        }
    }
}

/// Type of channel
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
#[derive(Default)]
pub enum SurfaceType {
    /// User-created channel
    #[default]
    User,
    /// Temporary onboarding channel
    Onboarding,
    /// System-managed channel
    System,
    /// A transit channel for inter-gateway comms
    Transit,
}

/// Protocol used by the channel
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
#[derive(Default)]
#[cfg_attr(test, derive(ts_rs::TS))]
#[cfg_attr(test, ts(export, export_to = "../www/default/src/generated/", rename_all = "lowercase"))]
pub enum ChannelProtocol {
    /// Agent-to-Agent protocol
    #[default]
    A2a,
    /// AP2 protocol (Agent Payments Protocol - extends A2A with VDC/VC/VP transformation)
    Ap2,
    /// Model Context Protocol
    Mcp,
    /// DIDComm for transit gateways
    DIDComm,
}

impl std::fmt::Display for ChannelProtocol {
    fn fmt(
        &self,
        f: &mut std::fmt::Formatter<'_>,
    ) -> std::fmt::Result {
        match self {
            ChannelProtocol::A2a => write!(f, "a2a"),
            ChannelProtocol::Ap2 => write!(f, "ap2"),
            ChannelProtocol::Mcp => write!(f, "mcp"),
            ChannelProtocol::DIDComm => write!(f, "didcomm"),
        }
    }
}

/// Target authentication configuration for proxy injection
///
/// Configures how the gateway injects credentials into requests
/// to external target services/agents. This is used when the gateway
/// needs to authenticate WITH external endpoints on behalf of managed agents.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetAuthConfig {
    /// Method for obtaining credentials
    pub method: TargetAuthMethod,

    /// UI hint for which auth preset was selected (bearer, basic, api_key, custom).
    /// Not used by the pipeline — purely for round-tripping through the UI without inference.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_type: Option<String>,

    /// Target identifier for credential lookup (used with CredentialLookup method)
    /// For StaticSecret method, this field is optional/unused.
    #[serde(default)]
    pub target_identifier: Option<String>,

    /// Fallback behavior when credentials are not found
    #[serde(default)]
    pub fallback: TargetAuthFallback,
}

/// Method for obtaining target authentication credentials
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum TargetAuthMethod {
    /// Look up credentials by target_identifier (not yet implemented)
    CredentialLookup,
    /// Use a static secret from the secrets store
    StaticSecret {
        /// Secret ID (secret_id field, not UUID) containing the credential value
        secret_id: String,
        /// Header name to inject (e.g., "Authorization", "X-API-Key")
        header_name: String,
        /// Header value format (e.g., "Bearer {value}", "{value}")
        /// The placeholder {value} will be replaced with the secret value
        #[serde(default = "default_header_format")]
        header_format: String,
    },
}

fn default_header_format() -> String {
    "{value}".to_string()
}

/// Fallback behavior when target credentials are not found
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "snake_case")]
pub enum TargetAuthFallback {
    /// Reject the request with 502 Bad Gateway
    #[default]
    Reject,
    /// Pass through the request without injecting credentials
    Passthrough,
}

/// Validates an outbound virtual channel alias.
///
/// Returns `Err` with a description if the alias is invalid:
/// - Must be non-empty
/// - Must be lowercase ASCII alphanumeric, hyphens, or underscores only
/// - Must not contain `/`, spaces, or uppercase letters
pub fn validate_outbound_alias(alias: &str) -> Result<(), String> {
    if alias.is_empty() {
        return Err("alias must not be empty".to_string());
    }
    if !alias
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_')
    {
        return Err(format!(
            "alias '{}' must only contain lowercase ASCII letters, digits, hyphens, or underscores",
            alias
        ));
    }
    Ok(())
}

/// Validate a per-VC `listen_path` override.
///
/// Path must:
/// - Start with `/`
/// - Contain no `..` segments (path traversal guard)
/// - Have at least one non-empty segment after the leading `/`
pub fn validate_outbound_listen_path(path: &str) -> Result<(), String> {
    if !path.starts_with('/') {
        return Err(format!("listen_path '{}' must start with '/'", path));
    }
    if path
        .split('/')
        .any(|seg| seg == "..")
    {
        return Err(format!("listen_path '{}' must not contain '..' segments", path));
    }
    if path
        .trim_start_matches('/')
        .is_empty()
    {
        return Err("listen_path must have at least one non-empty segment".to_string());
    }
    Ok(())
}

/// Bucket every outbound-enabled VC across all channels into the port that
/// should serve it. A VC's port is determined by its effective listen
/// address: `vc.listen_address ?? channel.outbound_listen_address`.
///
/// Returned map: `port → Vec<(channel, vcs assigned to this port)>`.
///
/// VCs whose effective address can't be mapped to a port, or whose port is
/// not in `configured_ports`, are skipped with a warning. Channels with no
/// VCs that resolve to any listener are skipped entirely. Both startup
/// (orchestrator) and hot-reload (channel_manager) call this so the
/// bucketing logic stays in lockstep.
pub fn group_outbound_vcs_by_port(
    surfaces: &[crate::config::agent_surface::AgentSurface],
    configured_ports: &[u16],
    map_address_to_port: impl Fn(&str) -> Option<u16>,
) -> std::collections::HashMap<
    u16,
    Vec<(crate::config::agent_surface::AgentSurface, Vec<crate::config::agent_surface::TransitPoint>)>,
> {
    use crate::config::agent_surface::{AgentSurface, TransitPoint};
    let mut by_port: std::collections::HashMap<u16, Vec<(AgentSurface, Vec<TransitPoint>)>> =
        std::collections::HashMap::new();

    for surface in surfaces {
        if surface.status == crate::config::agent_surface::SurfaceStatus::Disabled {
            continue;
        }
        let Some(ref transit) = surface.transit else {
            continue;
        };
        if transit.points.is_empty() {
            continue;
        }

        let channel_addr = transit
            .outbound_listen_address
            .as_deref();
        let channel_port = channel_addr.and_then(&map_address_to_port);

        let mut tps_by_port: std::collections::HashMap<u16, Vec<TransitPoint>> = std::collections::HashMap::new();
        for tp in &transit.points {
            let effective_addr = tp
                .listen_address
                .as_deref()
                .or(channel_addr);
            let tp_port = effective_addr
                .and_then(&map_address_to_port)
                .or(channel_port);
            let Some(p) = tp_port else {
                tracing::warn!(
                    "Surface '{}' transit point '{}' has no resolvable outbound listen address - skipping",
                    surface.name,
                    tp.alias
                );
                continue;
            };
            if !configured_ports.contains(&p) {
                tracing::warn!(
                    "Surface '{}' transit point '{}' references outbound port {} which is not configured - skipping",
                    surface.name,
                    tp.alias,
                    p
                );
                continue;
            }
            tps_by_port
                .entry(p)
                .or_default()
                .push(tp.clone());
        }

        if tps_by_port.is_empty() {
            tracing::warn!(
                "Surface '{}' has transit configured but no points resolved to a listener - skipping outbound",
                surface.name
            );
            continue;
        }

        for (port, tps) in tps_by_port {
            by_port
                .entry(port)
                .or_default()
                .push((surface.clone(), tps));
        }
    }

    by_port
}

/// A transit point whose outbound listen address does not resolve to a
/// configured outbound listener.
///
/// `group_outbound_vcs_by_port` silently skips these (logging a warning), which
/// means the transit point's outbound route is never served. That is a
/// gateway-breaking misconfiguration, so startup uses
/// [`find_unresolved_outbound_transit_points`] to detect them and refuse to
/// boot rather than come up with dead transit points.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnresolvedOutboundTransitPoint {
    pub surface_name: String,
    pub alias: String,
    /// The effective listen address (transit point override or surface default),
    /// or `None` when neither is configured.
    pub listen_address: Option<String>,
    pub reason: String,
}

/// Find every active transit point whose effective outbound listen address does
/// not resolve to a configured outbound listener port.
///
/// `map_address_to_port` must be the **outbound-restricted** resolver
/// (`map_url_to_port_for_type(addr, Some("outbound"))`) and `configured_ports`
/// the set of outbound listener ports, mirroring the inputs to
/// [`group_outbound_vcs_by_port`]. The returned problems are exactly the
/// transit points that bucketing would otherwise drop.
pub fn find_unresolved_outbound_transit_points(
    surfaces: &[crate::config::agent_surface::AgentSurface],
    configured_ports: &[u16],
    map_address_to_port: impl Fn(&str) -> Option<u16>,
) -> Vec<UnresolvedOutboundTransitPoint> {
    let mut problems = Vec::new();

    for surface in surfaces {
        if surface.status == crate::config::agent_surface::SurfaceStatus::Disabled {
            continue;
        }
        let Some(ref transit) = surface.transit else {
            continue;
        };
        if transit.points.is_empty() {
            continue;
        }

        let channel_addr = transit
            .outbound_listen_address
            .as_deref();

        for tp in &transit.points {
            let effective_addr = tp
                .listen_address
                .as_deref()
                .or(channel_addr);

            let Some(addr) = effective_addr else {
                problems.push(UnresolvedOutboundTransitPoint {
                    surface_name: surface.name.clone(),
                    alias: tp.alias.clone(),
                    listen_address: None,
                    reason: "no outbound listen address on the transit point or surface".to_string(),
                });
                continue;
            };

            match map_address_to_port(addr) {
                None => problems.push(UnresolvedOutboundTransitPoint {
                    surface_name: surface.name.clone(),
                    alias: tp.alias.clone(),
                    listen_address: Some(addr.to_string()),
                    reason: format!(
                        "address '{addr}' is not in the external_urls of any outbound listener (an inbound listener sharing the URL is ignored)"
                    ),
                }),
                Some(port) if !configured_ports.contains(&port) => {
                    problems.push(UnresolvedOutboundTransitPoint {
                        surface_name: surface.name.clone(),
                        alias: tp.alias.clone(),
                        listen_address: Some(addr.to_string()),
                        reason: format!("address '{addr}' resolves to port {port}, which is not a configured outbound listener"),
                    });
                }
                Some(_) => {}
            }
        }
    }

    problems
}

// ── Outbound Credential Delegation types ─────────────────────────────────────

// ── Workload Binding Attestation types ───────────────────────────────────────

/// Configures which fields appear in the VP workload binding attestation.
/// Controls what agent identity and caller context information is included
/// in the signed Verifiable Presentation attached to delegation audit events
/// and optionally injected into outbound Transit Point requests.
///
/// The v1 Transit Point-scoped shape sources caller context from a single
/// [`CallerContextSource`] and copies an operator-configured allowlist of
/// top-level caller claim names (`caller_context_fields`) verbatim into the
/// transit token / workload-binding VP. `agent_fields` optionally filters the
/// agent extension fields included in the binding.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct WorkloadBindingConfig {
    /// Agent extension field paths to include (dot-notation, e.g. "agentIdentity.llmInfo.model").
    /// These come from the agent's A2A/MCP extension payload validated against the channel schema.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub agent_fields: Vec<String>,

    /// Whether the workload-binding VP is produced for the owning Transit Point.
    /// When `false`, outbound identity injection keeps the flat `identityFields`
    /// credential-subject shape.
    #[serde(default)]
    pub enabled: bool,

    /// Where GW1 sources caller context from for this Transit Point.
    #[serde(default)]
    pub caller_source: CallerContextSource,

    /// Operator-configured allowlist of top-level caller claim names copied
    /// verbatim (output name == source name) from the selected caller-context
    /// source into the transit token and the workload-binding VP. Nested path
    /// extraction and aliasing are intentionally out of scope in v1; the
    /// selected claim value may be any JSON value.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub caller_context_fields: Vec<String>,

    /// When `true`, a caller-supplied VC/VP is chained into the Transit Point
    /// VP, upgrading caller assurance from `gateway_attested` to
    /// `caller_credential_chained`. Off by default.
    #[serde(default)]
    pub chain_caller_credentials: bool,

    /// When `true`, bind the VP to the request context (target, method/path,
    /// surface id, Transit Point, trace id) wherever that information is
    /// available. Defaults to `true`.
    #[serde(default = "default_true")]
    pub bind_request: bool,
}

/// Where GW1 sources caller context when building a workload-binding VP.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CallerContextSource {
    /// Caller context captured on the Access Point path and carried forward in
    /// the short-lived transit token (`X-Transit-Token`).
    #[default]
    TransitToken,
    /// Caller context extracted from a Bearer JWT presented on the Transit
    /// Point call's `Authorization` header. The header is stripped before the
    /// request is forwarded to GW2.
    AuthorizationBearerJwt,
    /// Caller context derived from a DID-authenticated session on the current
    /// Access Point hop. The caller must be authenticated via
    /// [`SourceAuthConfig::DidAuth`](crate::source_auth::models::SourceAuthConfig::DidAuth);
    /// the resolved DID becomes the caller identity and its SHA-256 hash the
    /// delegation-vault key.
    Did,
}

/// Structured validation errors for the Transit Point-scoped
/// [`WorkloadBindingConfig`]. Pure data — the API layer maps these into the
/// public HTTP error shape.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum WorkloadBindingValidationError {
    /// A `caller_context_fields` entry was blank or whitespace-only.
    #[error("caller_context_fields contains a blank claim name")]
    Blank,
    /// A `caller_context_fields` entry appeared more than once.
    #[error("caller_context_fields contains duplicate claim name '{name}'")]
    Duplicate { name: String },
    /// A `caller_context_fields` entry used nested-path (`a.b`) syntax, which
    /// is out of scope in v1 (top-level claim names only).
    #[error(
        "caller_context_fields entry '{name}' uses nested path syntax; only top-level claim names are supported in v1"
    )]
    Nested { name: String },
}

impl WorkloadBindingConfig {
    /// Validate the Transit Point-scoped caller allowlist: reject blank claim
    /// names, duplicate claim names, and nested-path syntax. The output field
    /// name always equals the source claim name in v1, so there is nothing to
    /// validate for aliasing (aliasing objects are rejected at deserialization
    /// because `caller_context_fields` is a plain string list).
    pub fn validate(&self) -> Result<(), WorkloadBindingValidationError> {
        let mut seen = std::collections::HashSet::with_capacity(
            self.caller_context_fields
                .len(),
        );
        for name in &self.caller_context_fields {
            let trimmed = name.trim();
            if trimmed.is_empty() {
                return Err(WorkloadBindingValidationError::Blank);
            }
            if trimmed.contains('.') {
                return Err(WorkloadBindingValidationError::Nested { name: name.clone() });
            }
            if !seen.insert(trimmed.to_string()) {
                return Err(WorkloadBindingValidationError::Duplicate { name: trimmed.to_string() });
            }
        }
        Ok(())
    }
}

/// Expand dot-notation identity fields into a nested JSON structure.
/// E.g. {"agentIdentity.llmInfo.model": "gpt-4"} → {"agentIdentity": {"llmInfo": {"model": "gpt-4"}}}
pub fn expand_dot_notation(flat: &std::collections::HashMap<String, serde_json::Value>) -> serde_json::Value {
    let mut root = serde_json::Map::new();
    for (path, value) in flat {
        let parts: Vec<&str> = path.split('.').collect();
        let mut current = &mut root;
        for (i, part) in parts.iter().enumerate() {
            if i == parts.len() - 1 {
                current.insert(part.to_string(), value.clone());
            } else {
                if !current.contains_key(*part)
                    || !current
                        .get(*part)
                        .is_some_and(|v| v.is_object())
                {
                    current.insert(part.to_string(), serde_json::Value::Object(serde_json::Map::new()));
                }
                current = current
                    .get_mut(*part)
                    .unwrap()
                    .as_object_mut()
                    .unwrap();
            }
        }
    }
    serde_json::Value::Object(root)
}

// ── Outbound Credential Binding types ────────────────────────────────────────

/// Binds a credential provider to a channel for outbound delegation.
/// When the gateway detects an outbound request needs credentials, it checks the
/// delegation vault and either injects a cached token or initiates consent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutboundCredentialBinding {
    /// FK to a configured CredentialProvider
    pub credential_provider_id: String,

    /// OAuth scopes to request (empty = use provider defaults)
    #[serde(default)]
    pub scopes: Vec<String>,

    /// When this credential is required
    #[serde(default)]
    pub required_for: CredentialRequirement,

    /// How to handle missing tokens
    #[serde(default)]
    pub consent_mode: ConsentMode,

    /// How to inject the token into outbound requests
    #[serde(default)]
    pub inject_as: CredentialInjection,

    /// Only used when `consent_mode = elicit`. How long the gateway waits for
    /// the user to respond to an MCP `elicitation/create` request (and/or for
    /// the OAuth callback to populate the vault) before failing the in-flight
    /// tool call. Default: 300s.
    #[serde(default = "default_elicit_timeout_secs")]
    pub elicit_timeout_secs: u64,

    /// Only used when `consent_mode = elicit`. What to do when the MCP client
    /// did not advertise the `elicitation` capability during `initialize`.
    #[serde(default)]
    pub elicit_fallback: ElicitFallback,
}

fn default_elicit_timeout_secs() -> u64 {
    300
}

/// When outbound credentials are required
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum CredentialRequirement {
    /// Every outbound request on this channel
    #[default]
    All,
    /// Only for specific MCP tools
    Tools(Vec<String>),
}

/// How to handle missing delegation tokens
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ConsentMode {
    /// Return a `consent_required` HTTP 401 + `application/problem+json` to
    /// the caller, including the authorization URL(s). This is the legacy
    /// behaviour and remains the default for backward compatibility. It is
    /// **not** the MCP elicitation spec — the caller is expected to interpret
    /// our custom payload out-of-band.
    #[default]
    OnDemand,
    /// Block channel access entirely until every binding's token already
    /// exists in the vault. Sessions that lack any required credential are
    /// refused at bind/initialize time with the authorization URL(s). Once
    /// granted, runtime traffic never sees a consent prompt.
    PreAuthorize,
    /// Spec-compliant MCP elicitation. When a tool call needs a credential
    /// that is missing, the gateway issues an `elicitation/create` request
    /// back to the MCP client over the open Streamable HTTP / SSE stream,
    /// referencing the authorization URL in the message, and waits for the
    /// user to either complete OAuth (vault populated via callback) or to
    /// `decline`/`cancel`. Requires the MCP client to have advertised the
    /// `elicitation` capability during `initialize`; see `elicit_fallback`.
    Elicit,
}

/// What to do when `consent_mode = elicit` but the MCP client did not declare
/// the `elicitation` capability during the `initialize` handshake.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ElicitFallback {
    /// Degrade to the legacy on-demand behaviour (HTTP 401 + consent_required).
    #[default]
    OnDemand,
    /// Fail the in-flight tool call with a JSON-RPC error.
    Fail,
}

/// How to inject delegated credentials into outbound requests
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum CredentialInjection {
    /// Authorization: Bearer {token}
    #[default]
    BearerHeader,
    /// Custom header with format string: e.g. { "name": "X-GitHub-Token", "format": "token {value}" }
    CustomHeader { name: String, format: String },
    /// JSON-RPC _meta field injection
    Meta { field: String },
}

/// Rate limit configuration for a channel
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    /// Maximum number of requests
    pub requests: u32,

    /// Time window in seconds
    pub window_secs: u64,

    /// Optional burst size (defaults to requests if not specified)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub burst: Option<u32>,
}

/// STS (`/oauth2/token`) runtime controls. All fields have safe defaults, so a
/// gateway configuration without an `sts` block behaves as if these defaults
/// were set.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct StsRuntimeConfig {
    /// Replay-protection backend selection for single-use ID-JAG redemption.
    #[serde(default)]
    pub replay_protection: ReplayProtectionConfig,
    /// Brute-force throttle for the token endpoint.
    #[serde(default)]
    pub token_endpoint_throttle: TokenEndpointThrottleConfig,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mcp_issuer: Option<crate::sts::mcp_profile::McpIssuerProfile>,

    #[serde(default, skip_serializing_if = "crate::sts::replay::McpReplayConfig::is_default")]
    pub mcp_replay: crate::sts::replay::McpReplayConfig,
}

/// Per-client-IP throttle for a sign-in endpoint (SAML login, CLI login). Off unless enabled. The
/// IP is resolved by [`crate::source_auth::client_ip`] from the proxies in [`ClientIpConfig`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginThrottleConfig {
    /// Master switch for the throttle. Defaults to `false`.
    #[serde(default)]
    pub enabled: bool,
    /// Per-client-IP limit. A client over it waits until its window rolls off.
    #[serde(default = "default_login_throttle_per_ip")]
    pub per_ip: RateLimitConfig,
}

impl Default for LoginThrottleConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            per_ip: default_login_throttle_per_ip(),
        }
    }
}

/// Which proxies may report the caller's address for per-client-IP limits (the SAML and CLI
/// login throttles). Separate from `tls.client_auth.trusted_proxies`, which only gates forwarded
/// client certificates.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ClientIpConfig {
    /// Proxy CIDRs whose `X-Forwarded-For` is read, or RFC 7239 `Forwarded` when a request has no
    /// `X-Forwarded-For`. Each listed proxy must append the address it saw to `X-Forwarded-For`
    /// or overwrite it. Empty means the TCP peer is always the client.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub trusted_proxies: Vec<ipnet::IpNet>,
}

fn default_login_throttle_per_ip() -> RateLimitConfig {
    RateLimitConfig {
        requests: 20,
        window_secs: 60,
        burst: None,
    }
}

/// Selects the replay-protection backend by name. The built-in backend is
/// `in_process`; additional backends may be registered at startup.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplayProtectionConfig {
    #[serde(default = "default_replay_backend")]
    pub backend: String,
}

impl Default for ReplayProtectionConfig {
    fn default() -> Self {
        Self {
            backend: default_replay_backend(),
        }
    }
}

fn default_replay_backend() -> String {
    "in_process".to_string()
}

/// Throttle for the token endpoint: bounds repeated attempts per client id and
/// per source address so credential guessing is rate-limited.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenEndpointThrottleConfig {
    /// Master switch for the throttle.
    #[serde(default = "sts_throttle_default_true")]
    pub enabled: bool,
    /// Count only failed client authentications (recommended) rather than every request.
    #[serde(default = "sts_throttle_default_true")]
    pub failed_attempts_only: bool,
    /// Per-`client_id` limit.
    #[serde(default = "default_throttle_per_client")]
    pub per_client: RateLimitConfig,
    /// Per-source-address limit (source read from `X-Forwarded-For` / `Forwarded`).
    #[serde(default = "default_throttle_per_ip")]
    pub per_ip: RateLimitConfig,
    /// Seconds a key stays blocked once over its limit (0 = until the window rolls off).
    #[serde(default = "default_throttle_lockout_secs")]
    pub lockout_secs: u64,
}

impl Default for TokenEndpointThrottleConfig {
    fn default() -> Self {
        Self {
            enabled: sts_throttle_default_true(),
            failed_attempts_only: sts_throttle_default_true(),
            per_client: default_throttle_per_client(),
            per_ip: default_throttle_per_ip(),
            lockout_secs: default_throttle_lockout_secs(),
        }
    }
}

fn sts_throttle_default_true() -> bool {
    true
}
fn default_throttle_per_client() -> RateLimitConfig {
    RateLimitConfig {
        requests: 10,
        window_secs: 60,
        burst: None,
    }
}
fn default_throttle_per_ip() -> RateLimitConfig {
    RateLimitConfig {
        requests: 60,
        window_secs: 60,
        burst: None,
    }
}
fn default_throttle_lockout_secs() -> u64 {
    300
}

/// Timeout configuration for a channel
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeoutConfig {
    /// Request timeout in seconds (overall request duration)
    #[serde(default = "default_request_timeout")]
    pub request_secs: u64,

    /// Connection timeout in seconds (time to establish connection)
    #[serde(default = "default_connect_timeout")]
    pub connect_secs: u64,

    /// Idle timeout in seconds (time between data frames of a buffered
    /// upstream response body; `0` disables it)
    #[serde(default = "default_idle_timeout")]
    pub idle_secs: u64,
}

impl Default for TimeoutConfig {
    fn default() -> Self {
        Self {
            request_secs: default_request_timeout(),
            connect_secs: default_connect_timeout(),
            idle_secs: default_idle_timeout(),
        }
    }
}

fn default_request_timeout() -> u64 {
    30
}

fn default_connect_timeout() -> u64 {
    10
}

fn default_idle_timeout() -> u64 {
    60
}

/// Retry policy configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetryConfig {
    /// Maximum number of retry attempts
    #[serde(default = "default_max_retries")]
    pub max_attempts: u32,

    /// Initial backoff delay in milliseconds
    #[serde(default = "default_initial_backoff")]
    pub initial_backoff_ms: u64,

    /// Maximum backoff delay in milliseconds
    #[serde(default = "default_max_backoff")]
    pub max_backoff_ms: u64,

    /// Backoff multiplier (exponential backoff)
    #[serde(default = "default_backoff_multiplier")]
    pub backoff_multiplier: f64,

    /// HTTP status codes that should trigger a retry
    #[serde(default = "default_retryable_statuses")]
    pub retryable_status_codes: Vec<u16>,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_attempts: default_max_retries(),
            initial_backoff_ms: default_initial_backoff(),
            max_backoff_ms: default_max_backoff(),
            backoff_multiplier: default_backoff_multiplier(),
            retryable_status_codes: default_retryable_statuses(),
        }
    }
}

fn default_max_retries() -> u32 {
    3
}

fn default_initial_backoff() -> u64 {
    100
}

fn default_max_backoff() -> u64 {
    5000
}

fn default_backoff_multiplier() -> f64 {
    2.0
}

fn default_retryable_statuses() -> Vec<u16> {
    vec![408, 429, 500, 502, 503, 504]
}

/// Circuit breaker configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CircuitBreakerConfig {
    /// Number of consecutive failures before opening the circuit
    #[serde(default = "default_failure_threshold")]
    pub failure_threshold: u32,

    /// Number of consecutive successes to close the circuit from half-open
    #[serde(default = "default_success_threshold")]
    pub success_threshold: u32,

    /// Time in seconds to wait before attempting to close an open circuit (half-open state)
    #[serde(default = "default_timeout_secs")]
    pub timeout_secs: u64,

    /// Time window in seconds for counting failures
    #[serde(default = "default_window_secs")]
    pub window_secs: u64,
}

impl Default for CircuitBreakerConfig {
    fn default() -> Self {
        Self {
            failure_threshold: default_failure_threshold(),
            success_threshold: default_success_threshold(),
            timeout_secs: default_timeout_secs(),
            window_secs: default_window_secs(),
        }
    }
}

fn default_failure_threshold() -> u32 {
    5
}

fn default_success_threshold() -> u32 {
    2
}

fn default_timeout_secs() -> u64 {
    60
}

fn default_window_secs() -> u64 {
    60
}

/// Traffic mirroring configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MirrorConfig {
    /// Mirror endpoint URL
    pub endpoint: String,

    /// Percentage of traffic to mirror (0-100)
    #[serde(default = "default_mirror_percentage")]
    pub percentage: u8,

    /// Whether to wait for mirror response (false = fire-and-forget)
    #[serde(default = "default_false")]
    pub wait_for_response: bool,

    /// Timeout for mirror requests in seconds
    #[serde(default = "default_mirror_timeout")]
    pub timeout_secs: u64,
}

fn default_mirror_percentage() -> u8 {
    100
}

fn default_mirror_timeout() -> u64 {
    5
}

/// MCP tool-level policy configuration
/// Defines OPA policies for controlling access to specific MCP methods/tools
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpToolPolicy {
    /// Unique identifier for this policy
    #[serde(default)]
    pub id: String,

    /// Policy name (human-readable)
    pub name: String,

    /// Description of what this policy controls
    #[serde(default)]
    pub description: String,

    /// OPA/Rego policy code
    /// This is evaluated with input containing: mcp.method, jwt, channel, request
    /// Should define an "allow" rule that returns true/false
    pub policy: String,

    /// Whether to enforce this policy (if false, policy is logged but not enforced)
    #[serde(default = "default_true")]
    pub enforce: bool,

    /// Priority/order for evaluation (lower numbers evaluated first)
    #[serde(default)]
    pub priority: i32,
}

/// Extension validation rules for a channel
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ExtensionRules {
    /// JSON Schema for structural validation and identity extraction
    /// - Validates the entire extension payload structure
    /// - Fields marked with "x-identity": true are used for computing identity hash
    #[serde(skip_serializing_if = "Option::is_none")]
    pub json_schema: Option<serde_json::Value>,

    /// Custom field matching rules
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rules: Vec<ValidationRule>,

    /// Per-URI extension filter rules (allow / strip / reject).
    /// Set by the surface-builder Extension Rules canvas element.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub filter_rules: Vec<ExtensionFilterRule>,

    /// Fallback action for extensions not matched by any `filter_rules` entry.
    /// Recognised values: "pass" (default), "strip", "reject".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_action: Option<String>,
}

/// Per-URI action rule used by the surface-builder Extension Rules element
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ExtensionFilterRule {
    /// Full extension URI (e.g. "https://a2a.dev/extensions/…")
    pub extension_uri: String,
    /// Action to apply: "require", "allow", "strip", or "reject"
    pub action: String,
    /// Optional additional condition (free-form, reserved for future use)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub condition: Option<String>,
}

/// x402 payment requirement
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct X402PaymentRequirement {
    /// Payment scheme (e.g., "exact", "upto")
    pub scheme: String,

    /// Blockchain network in CAIP-2 format (e.g., "eip155:8453" for Base)
    pub network: String,

    /// Amount in smallest unit (e.g., wei for EVM chains)
    pub amount: String,

    /// Token contract address (ERC20/SPL token address)
    /// Empty string or "native" indicates native token (ETH, SOL, etc.)
    #[serde(default)]
    pub asset: String,

    /// User-selected recipient identifier. Must match the `id` of an entry in
    /// the global x402 config's `recipient_addresses` list. This is the only
    /// recipient field the frontend / API caller is trusted to supply — the
    /// actual wallet address is resolved server-side from `recipient_id` +
    /// `network` and stored in `pay_to` during channel save and load.
    #[serde(default, rename = "recipientId", alias = "recipient_id")]
    pub recipient_id: String,

    /// Resolved on-chain recipient address. NEVER trusted from request input —
    /// always overwritten by the server-side `recipient_id` → address lookup
    /// in `validate_payment_policy`. Persisted on disk and read directly by
    /// the verification, settlement, and proxy layers, so they don't need to
    /// repeat the lookup on the hot path.
    #[serde(default, rename = "payTo", alias = "recipient")]
    pub pay_to: String,

    /// Maximum time in seconds for payment to be valid
    #[serde(rename = "maxTimeoutSeconds")]
    pub max_timeout_seconds: i32,

    /// Optional scheme-specific extra data (e.g., EIP-712 domain)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extra: Option<serde_json::Value>,
}

impl X402PaymentRequirement {
    /// Token contract address, or `None` when the requirement is for the network's native currency
    pub fn token_address(&self) -> Option<&str> {
        if self.asset.is_empty() || self.asset == "native" {
            None
        } else {
            Some(&self.asset)
        }
    }

    /// Asset transfer method from `extra` (`assetTransferMethod`, or legacy `asset_transfer_method`),
    /// defaulting to `transaction`
    pub fn asset_transfer_method(&self) -> String {
        self.extra
            .as_ref()
            .and_then(|extra| {
                extra
                    .get("assetTransferMethod")
                    .or_else(|| extra.get("asset_transfer_method"))
            })
            .and_then(|v| v.as_str())
            .unwrap_or("transaction")
            .to_string()
    }
}

/// x402 payment provider — who enforces the paywall.
///
/// `Local` (default) means this gateway runs the x402 challenge / verify /
/// settle itself. `AgentPay` delegates the *entire* payment interaction to a
/// remote payment gateway over the `fabric://` protocol: every
/// request is relayed to the configured payment surface, whose `402`
/// challenge is relayed back to the caller and whose `200` authorises the
/// request to proceed to this surface's own upstream.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "snake_case")]
pub enum X402Provider {
    /// This gateway enforces x402 locally (historical behaviour).
    #[default]
    Local,
    /// Delegate the whole payment interaction to a remote payment gateway.
    AgentPay,
}

impl X402Provider {
    /// Byte-compat helper: omit `provider` from serialized output when Local.
    pub fn is_local(&self) -> bool {
        matches!(self, X402Provider::Local)
    }
}

/// Which payment protocol the remote payment gateway enforces when
/// `X402Provider::AgentPay` delegates the whole paywall over `fabric://`. This
/// gateway's delegation transport is protocol-agnostic — the request/response
/// are relayed verbatim regardless of this marker — so it exists purely to make
/// the operator's choice explicit in config, the dashboard, and the delegation
/// audit log, rather than to change any enforcement behavior.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "snake_case")]
pub enum DelegatedPaymentRail {
    /// The remote payment surface enforces x402 (default).
    #[default]
    X402,
    /// The remote payment surface enforces MPP (Machine Payments Protocol).
    Mpp,
}

impl DelegatedPaymentRail {
    /// Byte-compat helper: omit `delegated_rail` from serialized output when X402.
    pub fn is_x402(&self) -> bool {
        matches!(self, DelegatedPaymentRail::X402)
    }
}

/// x402 verification mode
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
#[derive(Default)]
pub enum X402VerificationMode {
    /// Verify payments locally by checking on-chain (transaction hash)
    #[default]
    Local,
    /// Use external HTTP x402 facilitator for verification (x402 v2 spec)
    #[serde(rename = "external_facilitator")]
    ExternalFacilitator,
    /// Use another gateway as facilitator via DIDComm
    #[serde(rename = "fabric_gateway")]
    FabricGateway,
    /// Verify signed authorization off-chain (signature-based, spec-compliant)
    Signature,
    /// Mock mode for testing (accepts all payments)
    Mock,
}

/// x402 async verification mode (for gateway facilitator)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
#[derive(Default)]
pub enum X402AsyncMode {
    /// Always wait for verification to complete (blocking)
    Sync,
    /// Always return 202 Accepted immediately (non-blocking)
    Async,
    /// Try sync first, fallback to async if timeout (recommended)
    #[default]
    Hybrid,
}

/// x402 settlement mode
/// Works in conjunction with verification_mode to determine when and how to settle
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "lowercase")]
pub enum X402SettlementMode {
    /// Settle payment immediately after verification using the method from verification_mode
    /// - Local mode: Execute on-chain via embedded facilitator
    /// - Fabric Gateway: Delegate to other gateway which settles immediately
    /// - External Facilitator: Delegate to external service which settles immediately
    Immediate,
    /// Defer settlement to be done later, records depend on verification_mode
    /// - Local mode: Record locally for batch settlement
    /// - Fabric Gateway: Record on both gateways, signal when settled
    /// - External Facilitator: Record at facilitator service
    #[default]
    Deferred,
    /// No settlement (verification only)
    None,
}

/// x402 settlement worker configuration; its presence starts the worker
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct X402SettlementStorageConfig {
    /// Batch size for settlement processing
    #[serde(default = "default_batch_size")]
    pub batch_size: usize,

    /// Settlement interval in seconds
    #[serde(default = "default_settlement_interval")]
    pub settlement_interval_seconds: u64,

    /// Maximum retry attempts for failed settlements
    #[serde(default = "default_max_retries")]
    pub max_retries: u32,
}

fn default_transaction_path() -> String {
    "_storage/x402-transactions".to_string()
}

fn default_batch_size() -> usize {
    100
}

fn default_settlement_interval() -> u64 {
    60
}

fn default_settlement_max_retries() -> u32 {
    3
}

impl Default for X402SettlementStorageConfig {
    fn default() -> Self {
        Self {
            batch_size: default_batch_size(),
            settlement_interval_seconds: default_settlement_interval(),
            max_retries: default_settlement_max_retries(),
        }
    }
}

/// x402 transaction storage configuration (unified verification + settlement)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct X402TransactionStorageConfig {
    /// Filesystem storage directory for transaction records
    #[serde(default = "default_transaction_path")]
    pub filesystem_path: String,

    /// Retention period in days for transaction records (default: 7 days)
    /// Cleanup worker will delete transactions older than this
    #[serde(default = "default_transaction_retention_days")]
    pub retention_days: i64,
}

fn default_transaction_retention_days() -> i64 {
    7
}

impl Default for X402TransactionStorageConfig {
    fn default() -> Self {
        Self {
            filesystem_path: default_transaction_path(),
            retention_days: default_transaction_retention_days(),
        }
    }
}

/// x402 facilitator configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct X402FacilitatorConfig {
    /// Facilitator URL
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,

    /// Timeout in seconds
    #[serde(default = "default_facilitator_timeout")]
    pub timeout_seconds: u64,

    /// Maximum retry attempts
    #[serde(default = "default_facilitator_max_retries")]
    pub max_retries: u32,

    /// Initial backoff in milliseconds
    #[serde(default = "default_retry_backoff")]
    pub retry_backoff_ms: u64,
}

fn default_facilitator_timeout() -> u64 {
    10
}

fn default_facilitator_max_retries() -> u32 {
    3
}

fn default_retry_backoff() -> u64 {
    100
}

impl Default for X402FacilitatorConfig {
    fn default() -> Self {
        Self {
            url: Some("https://x402.coinbase.com".to_string()),
            timeout_seconds: default_facilitator_timeout(),
            max_retries: default_facilitator_max_retries(),
            retry_backoff_ms: default_retry_backoff(),
        }
    }
}

/// MCP payment trigger configuration.
///
/// Decides which `tools/call` invocations require payment. Three
/// explicit modes — see variants below.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum McpPaymentTriggers {
    /// Charge every `tools/call` request.
    All,
    /// Charge a `tools/call` request iff the tool name matches at least
    /// one of the regex patterns.
    Match {
        #[serde(default)]
        patterns: Vec<String>,
    },
    /// Charge every `tools/call` request EXCEPT those whose tool name
    /// matches at least one of the regex patterns.
    Exclude {
        #[serde(default)]
        patterns: Vec<String>,
    },
}

impl McpPaymentTriggers {
    /// Returns `true` if a `tools/call` for `tool_name` requires payment.
    /// Invalid regex patterns are silently treated as non-matching.
    pub fn requires_payment(
        &self,
        tool_name: &str,
    ) -> bool {
        match self {
            Self::All => true,
            Self::Match { patterns } => any_pattern_matches(patterns, tool_name),
            Self::Exclude { patterns } => !any_pattern_matches(patterns, tool_name),
        }
    }

    /// Validate that all regex patterns compile. Returns errors for each
    /// invalid pattern so operators see them at config-load time.
    pub fn validate(
        &self,
        channel_name: &str,
    ) -> Vec<String> {
        let patterns = match self {
            Self::All => return Vec::new(),
            Self::Match { patterns } | Self::Exclude { patterns } => patterns,
        };
        patterns
            .iter()
            .filter_map(|p| {
                if p.trim().is_empty() {
                    return None;
                }
                regex::Regex::new(p)
                    .err()
                    .map(|e| format!("Channel '{}': invalid mcp_payment_triggers regex '{}': {}", channel_name, p, e))
            })
            .collect()
    }
}

fn any_pattern_matches(
    patterns: &[String],
    s: &str,
) -> bool {
    if let Ok(set) = regex::RegexSet::new(
        patterns
            .iter()
            .filter(|p| !p.trim().is_empty()),
    ) {
        set.is_match(s)
    } else {
        patterns
            .iter()
            .filter(|p| !p.trim().is_empty())
            .any(|p| {
                regex::Regex::new(p)
                    .map(|r| r.is_match(s))
                    .unwrap_or(false)
            })
    }
}

#[cfg(test)]
mod integration_category_tests {
    use super::IntegrationCategory;

    fn category(enum_value: &str) -> IntegrationCategory {
        serde_json::from_value(serde_json::json!({
            "enum_value": enum_value,
            "name": "Name",
            "description": "Description"
        }))
        .unwrap()
    }

    #[test]
    fn a_legacy_channel_category_loads_as_surface() {
        assert_eq!(category("channel").enum_value, "surface");
    }

    #[test]
    fn other_category_values_load_unchanged() {
        for value in ["surface", "general", "connection_point", "audit"] {
            assert_eq!(category(value).enum_value, value);
        }
    }

    fn categories(config: &super::IntegrationConfig) -> Vec<&str> {
        config
            .categories
            .iter()
            .map(|c| c.enum_value.as_str())
            .collect()
    }

    #[test]
    fn a_config_without_the_audit_category_gains_the_built_in_one() {
        let mut config = super::IntegrationConfig::default_config();
        config
            .categories
            .retain(|c| c.enum_value == "general" || c.enum_value == "gateway");

        assert_eq!(config.add_missing_built_in_categories(), vec!["audit".to_string()]);
        assert_eq!(categories(&config), vec!["general", "gateway", "audit"]);
        assert!(
            config
                .add_missing_built_in_categories()
                .is_empty(),
            "adding is idempotent"
        );
    }

    #[test]
    fn an_operator_audit_category_is_kept_and_other_categories_are_not_added() {
        let mut config = super::IntegrationConfig::default_config();
        config
            .categories
            .retain(|c| c.enum_value == "audit");
        config.categories[0].name = "Compliance feed".to_string();

        assert!(
            config
                .add_missing_built_in_categories()
                .is_empty()
        );
        assert_eq!(categories(&config), vec!["audit"]);
        assert_eq!(config.categories[0].name, "Compliance feed");
    }
}

#[cfg(test)]
mod mcp_payment_triggers_tests {
    use super::McpPaymentTriggers;

    #[test]
    fn all_mode_charges_every_tool() {
        let t = McpPaymentTriggers::All;
        assert!(t.requires_payment("anything"));
        assert!(t.requires_payment(""));
    }

    #[test]
    fn match_mode_requires_regex_hit() {
        let t = McpPaymentTriggers::Match {
            patterns: vec!["^paid_".to_string(), "premium$".to_string()],
        };
        assert!(t.requires_payment("paid_search"));
        assert!(t.requires_payment("go_premium"));
        assert!(!t.requires_payment("free_tool"));
    }

    #[test]
    fn match_mode_with_empty_patterns_never_charges() {
        let t = McpPaymentTriggers::Match { patterns: vec![] };
        assert!(!t.requires_payment("anything"));
    }

    #[test]
    fn exclude_mode_inverts() {
        let t = McpPaymentTriggers::Exclude {
            patterns: vec!["^free_".to_string()],
        };
        assert!(!t.requires_payment("free_search"));
        assert!(t.requires_payment("paid_search"));
    }

    #[test]
    fn exclude_mode_with_empty_patterns_charges_everything() {
        let t = McpPaymentTriggers::Exclude { patterns: vec![] };
        assert!(t.requires_payment("anything"));
    }

    #[test]
    fn invalid_regex_is_skipped() {
        let t = McpPaymentTriggers::Match {
            patterns: vec!["[invalid".to_string(), "^ok$".to_string()],
        };
        assert!(t.requires_payment("ok"));
        assert!(!t.requires_payment("not_ok"));
    }

    #[test]
    fn whitespace_only_pattern_is_skipped() {
        let t = McpPaymentTriggers::Match {
            patterns: vec!["   ".to_string()],
        };
        assert!(!t.requires_payment("anything"));
    }

    #[test]
    fn serde_round_trip_match() {
        let t = McpPaymentTriggers::Match {
            patterns: vec!["^paid_".to_string()],
        };
        let json = serde_json::to_string(&t).unwrap();
        assert!(json.contains("\"mode\":\"match\""));
        let back: McpPaymentTriggers = serde_json::from_str(&json).unwrap();
        assert_eq!(back, t);
    }

    #[test]
    fn serde_all_has_no_patterns() {
        let t = McpPaymentTriggers::All;
        let json = serde_json::to_string(&t).unwrap();
        assert_eq!(json, r#"{"mode":"all"}"#);
    }
}

/// A2A method filter for payment triggers
/// Allows filtering by JSON-RPC method and optional message content regex
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct A2AMethodFilter {
    /// JSON-RPC method name (e.g., "SendMessage", "GetTask", "ListTasks")
    pub method: String,

    /// Optional regex patterns to match message content
    /// For methods with message payloads (SendMessage, SendStreamingMessage),
    /// payment is only required if the message matches at least one pattern
    /// Empty list means match all requests for this method
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub message_patterns: Vec<String>,
}

/// Facilitator key configuration with private key and derived address
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FacilitatorKeyConfig {
    /// Private key (hex-encoded, 0x-prefixed) or environment variable reference (e.g., "$FACILITATOR_KEY_BASE")
    pub private_key: String,

    /// Ethereum address derived from the private key (public information, doesn't need to be obfuscated)
    pub address: String,
}

/// x402 protocol configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct X402Config {
    /// Whether x402 payments are required for this channel
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Payment provider — `local` (this gateway) or `agent_pay` (delegate the
    /// whole paywall to a remote payment gateway over `fabric://`).
    #[serde(default, skip_serializing_if = "X402Provider::is_local")]
    pub provider: X402Provider,

    /// Connected peer gateway id that enforces payment when
    /// `provider = agent_pay`. Resolved to a DID at runtime via the gateway store.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payment_gateway_id: Option<String>,

    /// Surface id of the remote payment surface on `payment_gateway_id`.
    /// Together they form `fabric://{payment_gateway_id}/{payment_surface_id}`.
    #[serde(default, skip_serializing_if = "Option::is_none", alias = "payment_channel_id")]
    pub payment_surface_id: Option<String>,

    /// Which payment protocol the delegated surface enforces (`x402`,
    /// default, or `mpp`). Informational only when `provider = agent_pay` —
    /// the fabric delegation transport already relays either protocol
    /// transparently — but makes the operator's choice explicit in config,
    /// the dashboard, and the delegation audit log.
    #[serde(default, skip_serializing_if = "DelegatedPaymentRail::is_x402")]
    pub delegated_rail: DelegatedPaymentRail,

    /// Facilitator endpoint for payment verification/settlement
    /// Example: "https://x402.coinbase.com"
    #[serde(skip_serializing_if = "Option::is_none")]
    pub facilitator_url: Option<String>,

    /// Supported payment schemes (e.g., ["exact", "upto"])
    #[serde(default)]
    pub supported_schemes: Vec<String>,

    /// Supported blockchain networks (e.g., ["base", "ethereum", "solana"])
    #[serde(default)]
    pub supported_networks: Vec<String>,

    /// Payment requirements for this channel
    /// Multiple requirements allow clients to choose their preferred payment method
    #[serde(default)]
    pub payment_requirements: Vec<X402PaymentRequirement>,

    /// Payment verification mode
    #[serde(default)]
    pub verification_mode: X402VerificationMode,

    /// Payment settlement mode
    #[serde(default)]
    pub settlement_mode: X402SettlementMode,

    /// RPC endpoints for blockchain networks
    /// Map of network name to RPC endpoint URL
    /// Example: {"base": "https://mainnet.base.org", "ethereum": "https://eth.llamarpc.com"}
    #[serde(default)]
    pub rpc_endpoints: std::collections::HashMap<String, String>,

    /// Minimum confirmations required for transaction verification
    /// 0 = accept mempool transactions (fast but risky)
    /// 1+ = wait for confirmations (slower but more secure)
    #[serde(default)]
    pub min_confirmations: u64,

    /// Accept transactions in mempool (not yet mined)
    /// Only applies when min_confirmations = 0
    #[serde(default)]
    pub accept_mempool_tx: bool,

    /// MCP payment trigger mode (regex-based). See [`McpPaymentTriggers`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mcp_payment_triggers: Option<McpPaymentTriggers>,

    /// For A2A/AP2: structured method filters with optional message content regex
    /// Each filter specifies a JSON-RPC method and optional message patterns
    /// If None or empty, all requests require payment
    /// If specified, only matching method+message combinations trigger payment
    #[serde(skip_serializing_if = "Option::is_none")]
    pub a2a_method_filters: Option<Vec<A2AMethodFilter>>,

    /// DEPRECATED: Legacy A2A methods list (use a2a_method_filters instead)
    /// Maintained for backward compatibility
    #[serde(skip_serializing_if = "Option::is_none")]
    pub a2a_methods: Option<Vec<String>>,

    /// Settlement storage configuration
    #[serde(skip_serializing_if = "Option::is_none")]
    pub settlement_storage: Option<X402SettlementStorageConfig>,

    /// Transaction storage configuration (unified verification + settlement)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transaction_storage: Option<X402TransactionStorageConfig>,

    /// Facilitator configuration
    #[serde(skip_serializing_if = "Option::is_none")]
    pub facilitator: Option<X402FacilitatorConfig>,

    /// Gateway facilitator ID (for verification_mode = "fabric_gateway")
    /// This is the ID of a connected gateway (from /api/v1/gateways)
    /// The gateway's DID will be resolved at runtime
    /// Example: "550e8400-e29b-41d4-a716-446655440000"
    #[serde(skip_serializing_if = "Option::is_none")]
    pub facilitator_gateway_id: Option<String>,

    /// Async verification mode (for gateway facilitator)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verification_async: Option<X402AsyncMode>,

    /// Facilitator private keys and addresses for settlement
    /// Map of chain ID to key config with private_key and address
    /// e.g., {"eip155:8453": {"private_key": "0x..." or "$ENV_VAR", "address": "0x..."}}
    /// Required when verification_mode = "local" or settlement_mode = "local"
    /// Private keys can be environment variable references (e.g., "$FACILITATOR_KEY_BASE")
    /// Addresses are public and don't need obfuscation
    #[serde(skip_serializing_if = "Option::is_none")]
    pub facilitator_private_keys: Option<std::collections::HashMap<String, FacilitatorKeyConfig>>,

    /// Per-chain configuration for embedded facilitator
    /// TODO: Add support for chain-specific settings (eip1559, flashblocks, rate limits, timeouts)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chain_configs: Option<std::collections::HashMap<String, serde_json::Value>>,

    /// Verification timeout in milliseconds (for hybrid mode)
    /// If verification takes longer, switch to async mode
    /// Default: 10000 (10 seconds)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verification_timeout_ms: Option<u64>,

    /// Settlement timeout in milliseconds (for immediate mode)
    /// Maximum time to wait for settlement response from gateway/external facilitator
    /// Default: 60000 (60 seconds)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub settlement_timeout_ms: Option<u64>,
}

impl Default for X402Config {
    fn default() -> Self {
        Self {
            enabled: true,
            provider: X402Provider::Local,
            payment_gateway_id: None,
            payment_surface_id: None,
            delegated_rail: DelegatedPaymentRail::X402,
            facilitator_url: None,
            supported_schemes: vec!["exact".to_string()],
            supported_networks: vec!["base".to_string()],
            payment_requirements: vec![],
            verification_mode: X402VerificationMode::Local,
            settlement_mode: X402SettlementMode::Deferred,
            rpc_endpoints: std::collections::HashMap::new(),
            min_confirmations: 0,
            accept_mempool_tx: true,
            mcp_payment_triggers: None,
            a2a_method_filters: None,
            a2a_methods: None,
            settlement_storage: None,
            transaction_storage: None,
            facilitator: None,
            facilitator_gateway_id: None,
            verification_async: None,
            facilitator_private_keys: None,
            chain_configs: None,
            verification_timeout_ms: Some(10000), // 10 second default timeout
            settlement_timeout_ms: Some(60000),   // 60 second default timeout
        }
    }
}

/// Custom metadata injection target (for MCP protocol)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
#[derive(Default)]
pub enum MetadataInjectionTarget {
    /// Inject into JSON-RPC _meta field (protocol-level, transport-agnostic)
    Meta,
    /// Inject as HTTP headers (transport-level, HTTP only)
    Headers,
    /// Inject into both _meta field and HTTP headers
    #[default]
    Both,
}

/// Custom metadata for a channel
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomMetadata {
    /// Whether extension metadata is enabled for this channel
    #[serde(default = "default_false")]
    pub enabled: bool,

    /// JSON Schema for the metadata structure
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload: Option<serde_json::Value>,

    /// Where to inject metadata for MCP protocol (meta, headers, or both)
    /// Default: both (for maximum compatibility)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub injection_target: Option<MetadataInjectionTarget>,
}

/// Trust Recorder — writes trust-registry records via TrAdmin DIDComm on the
/// MA→AP response leg. One entry per target trust registry; each entry
/// controls which built-in triples plus custom actions get written.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TrustRecorderConfig {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub entries: Vec<TrustRecorderEntry>,
}

/// Cap on `TrustRecorderConfig::entries`. Mirrored by the UI panel
/// (`www/default/src/components/surface-builder/elements/trust-recorder/definition.ts`).
pub const TRUST_RECORDER_ENTRIES_MAX: usize = 10;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustRecorderEntry {
    /// Target trust-registry id (referenced from the gateway's TR store).
    pub trust_registry_id: String,
    /// Issuer DID — written as the `entity_id` on any custom resource
    /// whose `entity_target` is `Issuer`.
    pub issuer_did: String,
    /// Trust anchor DID that asserts these records. Written as the
    /// `authority_id` on every emitted `TrAdminRecordRequest`. Required —
    /// without a distinct authority the recorder degenerates to
    /// self-assertion, which some trust registries reject.
    pub authority_did: String,
    /// authority=<authority_did>, entity=<agent DID>, action="is", resource="ownedAgent"
    #[serde(default = "default_false")]
    pub include_owned_agent: bool,
    /// Extra records the surface author wants written. Each entry becomes
    /// authority=<authority_did>, entity=<issuer_did | agent DID> (per
    /// `entity_target`), action=<action>, resource=<resource>.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub custom_resources: Vec<CustomResource>,
}

/// A single custom record on a `TrustRecorderEntry`. Action and resource
/// are free-form labels; `entity_target` selects which DID to write as the
/// `entity_id` on the emitted `TrAdminRecordRequest`; `record_type`
/// selects the TrAdmin record type (typically `"recognition"` or
/// `"authorization"`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomResource {
    pub action: String,
    pub resource: String,
    pub entity_target: EntityTarget,
    #[serde(default = "default_record_type")]
    pub record_type: String,
}

fn default_record_type() -> String {
    "recognition".to_string()
}

/// Which DID becomes `entity_id` on a `CustomResource` record.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EntityTarget {
    /// Use the entry's `issuer_did`.
    Issuer,
    /// Use the resolved agent DID at record time.
    Agent,
}

/// A single validation rule
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ValidationRule {
    /// Check if a field equals a specific value
    Equals {
        /// JSON path to the field (e.g., "agentIdentity.provisioningInfo.cloudProvider")
        path: String,
        /// Expected value
        value: serde_json::Value,
    },
    /// Check if a field does not equal a specific value
    NotEquals {
        /// JSON path to the field
        path: String,
        /// Value that should not match
        value: serde_json::Value,
    },
    /// Check if a field matches a regex pattern
    Regex {
        /// JSON path to the field
        path: String,
        /// Regex pattern
        pattern: String,
    },
    /// Check if a field exists
    Exists {
        /// JSON path to the field
        path: String,
    },
    /// Check if a field is within a range (for numbers)
    Range {
        /// JSON path to the field
        path: String,
        /// Minimum value (inclusive, optional)
        min: Option<f64>,
        /// Maximum value (inclusive, optional)
        max: Option<f64>,
    },
    /// Check if a field is in a list of allowed values
    OneOf {
        /// JSON path to the field
        path: String,
        /// List of allowed values
        values: Vec<serde_json::Value>,
    },
    /// Check if all array elements match a specific type and optionally specific values
    ArrayAll {
        /// JSON path to the field
        path: String,
        /// Required type for all elements ("string", "number", "boolean")
        element_type: String,
        /// Optional: specific values that all elements must match
        values: Option<Vec<serde_json::Value>>,
    },
    /// Check if any array element matches a specific type and optionally specific values
    ArrayAny {
        /// JSON path to the field
        path: String,
        /// Required type for matching elements ("string", "number", "boolean")
        element_type: String,
        /// Optional: specific values that at least one element must match
        values: Option<Vec<serde_json::Value>>,
    },
    /// Check array length constraints
    ArrayLength {
        /// JSON path to the field
        path: String,
        /// Minimum array length (inclusive, optional)
        min: Option<usize>,
        /// Maximum array length (inclusive, optional)
        max: Option<usize>,
    },
}

/// x402 facilitator mode configuration
/// Controls which facilitator features are enabled at the gateway level
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FacilitatorMode {
    /// Enable fabric-based facilitator (DIDComm verification requests from other gateways)
    /// When true: Gateway can receive x402 verification requests via DIDComm
    /// When false: DIDComm verification requests are rejected with error
    #[serde(default)]
    pub facilitator_via_fabric: bool,

    /// Enable HTTP-based facilitator (standard x402 specification endpoints)
    /// When true: Exposes POST /api/x402/verify, POST /api/x402/settle, GET /api/x402/supported
    /// When false: HTTP facilitator routes are not registered
    #[serde(default)]
    pub facilitator_via_http: bool,

    /// Enable x402 e2e test endpoints (/protected, /protected-permit2,
    /// /protected-solana-*, /health, /close). These are UNAUTHENTICATED
    /// conformance-test surfaces and `POST /close` is a control endpoint —
    /// keep disabled in any non-test deployment.
    #[serde(default)]
    pub enable_test_endpoints: bool,
}

/// Configuration for the Affinidi Trust Fabric Gateway server
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayConfig {
    /// Active runtime agent surfaces, populated by the agent-surface store after
    /// gateway.json is parsed. Never serialised — surfaces live in their own
    /// per-surface store on disk.
    #[serde(default, skip)]
    pub surfaces: Vec<crate::config::agent_surface::AgentSurface>,

    /// TLS certificate configuration
    pub tls: TlsConfig,

    /// A2A protocol specific settings
    #[serde(default)]
    pub a2a: A2aConfig,

    /// MCP protocol specific settings
    #[serde(default)]
    pub mcp: McpConfig,

    /// Logging configuration
    #[serde(default)]
    pub logging: LoggingConfig,

    /// Extension inspection configuration
    #[serde(default)]
    pub extension_inspection: ExtensionInspectionConfig,

    /// integration configuration
    pub integration: IntegrationConfig,

    /// x402 facilitator mode configuration (gateway-level control)
    #[serde(default)]
    pub facilitator_mode: FacilitatorMode,

    /// x402 payment protocol headers (loaded from x402.json)
    /// Not serialized to gateway config, loaded separately at startup
    #[serde(skip)]
    pub x402_headers: X402Headers,
}

/// x402 HTTP headers configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct X402Headers {
    pub payment_required: String,
    pub payment_signature: String,
    pub payment_response: String,
}

impl Default for X402Headers {
    fn default() -> Self {
        Self {
            payment_required: "PAYMENT-REQUIRED".to_string(),
            payment_signature: "PAYMENT-SIGNATURE".to_string(),
            payment_response: "PAYMENT-RESPONSE".to_string(),
        }
    }
}

/// Configuration file paths (all JSON config files)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigFilePaths {
    /// Gateway configuration file path - defines ports, bind addresses, and available routes
    #[serde(default = "default_gateway_config_path")]
    pub gateway: String,

    /// Metrics configuration file path - defines OpenTelemetry and CloudWatch settings
    #[serde(default = "default_metrics_config_path")]
    pub metrics: String,

    /// RBAC configuration file path - defines role-based permissions
    #[serde(default = "default_rbac_config_path")]
    pub rbac: String,

    /// Resource-limits configuration file path - defines per-dimension caps on
    /// how many entities the appliance will hold (secrets, surfaces, policies, …).
    #[serde(default = "default_limits_config_path")]
    pub limits: String,

    /// SAML configuration file path (Azure AD or other SAML IdP configuration)
    #[serde(default = "crate::auth::auth_config::default_saml_config_path")]
    pub saml: String,

    /// x402 payment configuration file path - defines blockchain networks, recipients, and payment settings
    #[serde(default = "default_payment_policy_path")]
    pub x402: String,

    /// X402Proxy configuration file path - defines wallets and networks for MCP proxy payments
    #[serde(default = "default_x402_proxy_config_path", alias = "mcpx402")]
    pub x402_proxy: String,

    /// Test endpoints configuration file path - defines deployment-specific test endpoint values
    #[serde(default = "default_test_endpoints_config_path")]
    pub test_endpoints: String,

    /// Directory (relative to the config dir, or absolute) scanned at
    /// startup for `.json` agent-surface starter templates. Files found
    /// here are seeded into the on-disk template store as builtins.
    #[serde(default = "default_agent_surface_templates_dir")]
    pub agent_surface_templates_dir: String,
}

impl Default for ConfigFilePaths {
    fn default() -> Self {
        Self {
            gateway: default_gateway_config_path(),
            metrics: default_metrics_config_path(),
            rbac: default_rbac_config_path(),
            limits: default_limits_config_path(),
            saml: crate::auth::auth_config::default_saml_config_path(),
            x402: default_payment_policy_path(),
            x402_proxy: default_x402_proxy_config_path(),
            test_endpoints: default_test_endpoints_config_path(),
            agent_surface_templates_dir: default_agent_surface_templates_dir(),
        }
    }
}

/// Storage paths (all directories where data is persisted)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoragePaths {
    /// Path to store last-known good configuration cache
    #[serde(default = "default_config_cache_path")]
    pub config_cache: String,

    /// Identity records storage path - stores DID identity information
    #[serde(default = "default_identity_storage_path")]
    pub identities: String,

    /// Path to store settings data (badge threshold, metrics retention, etc.)
    #[serde(default = "default_settings_storage_path")]
    pub settings: String,

    /// Path to store trust registry configurations
    #[serde(default = "default_trust_registries_storage_path")]
    pub trust_registries: String,

    /// Path to store notifications
    #[serde(default = "default_notifications_storage_path")]
    pub notifications: String,

    /// Path to store notification templates (admin and user welcome messages)
    #[serde(default = "default_notification_templates_storage_path")]
    pub notification_templates: String,

    /// Storage path for connection points
    #[serde(default = "default_connection_points_storage_path")]
    pub connection_points: String,

    /// Secrets storage path (for filesystem backend)
    #[serde(default = "default_secrets_storage_path")]
    pub secrets: String,

    /// API keys storage path
    #[serde(default = "default_apikeys_storage_path")]
    pub apikeys: String,

    /// Certificates storage path
    #[serde(default = "default_certificates_storage_path")]
    pub certificates: String,

    /// Path to store MCP Proxy configurations
    #[serde(default = "default_mcp_proxies_storage_path")]
    pub mcp_proxies: String,

    /// Path to store A2A Proxy configurations
    #[serde(default = "default_a2a_proxies_storage_path")]
    pub a2a_proxies: String,

    /// Path to store Integration definitions (notifiers)
    #[serde(default = "default_integrations_storage_path")]
    pub integrations: String,

    /// Path to store Integration triggers (user and gateway integrations)
    #[serde(default = "default_integration_triggers_storage_path")]
    pub integration_triggers: String,

    /// Path to store Webhook configurations
    #[serde(default = "default_webhooks_storage_path")]
    pub webhooks: String,

    /// Storage path for VC issuer keys and DID documents
    #[serde(default = "default_vc_keys_path")]
    pub vc_keys: String,

    /// Storage path for metrics data
    #[serde(default = "default_metrics_storage_path")]
    pub metrics: String,

    /// Path to store passkey credentials (used when auth_mode = passkey)
    #[serde(default = "crate::auth::auth_config::default_passkey_storage_path")]
    pub passkeys: String,

    /// Path to store Customer Terms definitions and acceptance records
    #[serde(default = "default_terms_storage_path")]
    pub terms: String,

    /// Path to store user avatars
    #[serde(default = "crate::auth::auth_config::default_avatars_storage_path")]
    pub avatars: String,

    /// Path to store gateway configurations
    #[serde(default = "default_gateways_storage_path")]
    pub gateways: String,

    /// Path to store mediator configurations
    #[serde(default = "default_mediators_storage_path")]
    pub mediators: String,

    /// Path to store messages
    #[serde(default = "default_messages_storage_path")]
    pub messages: String,

    /// Path to store x402 transactions (unified verification + settlement)
    #[serde(default = "default_x402_transactions_storage_path")]
    pub x402_transactions: String,

    /// Path to store MPP payment transactions (audit trail)
    #[serde(default = "default_mpp_transactions_storage_path")]
    pub mpp_transactions: String,

    /// Path to store session data (persistent sessions across restarts)
    #[serde(default = "default_sessions_storage_path")]
    pub sessions: String,

    /// Path to persist system metrics (CPU/memory) history
    #[serde(default = "default_system_metrics_storage_path")]
    pub system_metrics: String,

    /// Path to store reusable OPA policy definitions
    #[serde(default = "default_policy_definitions_storage_path")]
    pub policy_definitions: String,

    /// Path to store appliance-wide (global) policy assignments
    #[serde(default = "default_global_policies_storage_path")]
    pub global_policies: String,

    /// Path to store issuer configurations (was: `departments` before the
    /// concept rename). Accepts the legacy `departments` key on input for
    /// backward compatibility with existing gateway configs.
    #[serde(default = "default_issuers_storage_path", alias = "departments")]
    pub issuers: String,

    /// Path to store authority records (local trust-anchor register)
    #[serde(default = "default_authorities_storage_path")]
    pub authorities: String,

    /// Path to store OAuth credential provider configurations
    #[serde(default = "default_credential_providers_storage_path")]
    pub credential_providers: String,

    /// Path to store delegation vault tokens (encrypted OAuth tokens per agent+user+provider)
    #[serde(default = "default_delegation_vault_storage_path")]
    pub delegation_vault: String,

    /// Path to store Agent Surface configurations
    #[serde(default = "default_agent_surfaces_storage_path")]
    pub agent_surfaces: String,

    /// Path to store agent surface templates (builtin + user-authored
    /// bundles of pre-configured surface items). Builtins are seeded
    /// from `<config_dir>/agent_surface_templates/*.json` at startup.
    #[serde(default = "default_agent_surface_templates_storage_path")]
    pub agent_surface_templates: String,

    /// Path for backup/restore working files (backup.agbak, local_backups/)
    #[serde(default = "default_backup_restore_storage_path")]
    pub backup_restore: String,

    /// Path to the persisted identity hash pepper file used for stable
    /// credential-derived DID hashing across restarts.
    #[serde(default = "default_identity_hash_pepper_file_path")]
    pub identity_hash_pepper: String,
}

impl Default for StoragePaths {
    fn default() -> Self {
        Self {
            config_cache: default_config_cache_path(),
            identities: default_identity_storage_path(),
            settings: default_settings_storage_path(),
            trust_registries: default_trust_registries_storage_path(),
            notifications: default_notifications_storage_path(),
            notification_templates: default_notification_templates_storage_path(),
            connection_points: default_connection_points_storage_path(),
            secrets: default_secrets_storage_path(),
            apikeys: default_apikeys_storage_path(),
            certificates: default_certificates_storage_path(),
            mcp_proxies: default_mcp_proxies_storage_path(),
            a2a_proxies: default_a2a_proxies_storage_path(),
            integrations: default_integrations_storage_path(),
            integration_triggers: default_integration_triggers_storage_path(),
            webhooks: default_webhooks_storage_path(),
            vc_keys: default_vc_keys_path(),
            metrics: default_metrics_storage_path(),
            passkeys: crate::auth::auth_config::default_passkey_storage_path(),
            terms: default_terms_storage_path(),
            avatars: crate::auth::auth_config::default_avatars_storage_path(),
            gateways: default_gateways_storage_path(),
            mediators: default_mediators_storage_path(),
            messages: default_messages_storage_path(),
            x402_transactions: default_x402_transactions_storage_path(),
            mpp_transactions: default_mpp_transactions_storage_path(),
            sessions: default_sessions_storage_path(),
            system_metrics: default_system_metrics_storage_path(),
            policy_definitions: default_policy_definitions_storage_path(),
            global_policies: default_global_policies_storage_path(),
            issuers: default_issuers_storage_path(),
            authorities: default_authorities_storage_path(),
            credential_providers: default_credential_providers_storage_path(),
            delegation_vault: default_delegation_vault_storage_path(),
            agent_surfaces: default_agent_surfaces_storage_path(),
            agent_surface_templates: default_agent_surface_templates_storage_path(),
            backup_restore: default_backup_restore_storage_path(),
            identity_hash_pepper: default_identity_hash_pepper_file_path(),
        }
    }
}

/// Bootstrap configuration - loaded from file to determine how to load full config
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BootstrapConfig {
    /// Configuration source type: "dynamodb" or "file"
    #[serde(default = "default_channel_config_source")]
    pub channel_config_source: String,

    /// DynamoDB table name (required if channel_config_source is "dynamodb")
    pub dynamodb_table: Option<String>,

    /// AWS region (optional, uses default credential chain region if not specified)
    pub aws_region: Option<String>,

    /// AWS profile name (optional, uses default profile if not specified)
    /// This corresponds to the profile name in ~/.aws/credentials and ~/.aws/config
    pub aws_profile: Option<String>,

    /// TLS configuration (required)
    pub tls: TlsConfig,

    /// Encryption at rest configuration
    #[serde(default)]
    pub encryption: EncryptionConfig,

    /// A2A protocol specific settings
    #[serde(default)]
    pub a2a: A2aConfig,

    /// MCP protocol specific settings
    #[serde(default)]
    pub mcp: McpConfig,

    /// OOB connection configuration
    #[serde(default)]
    pub oob_connection: OobConnectionConfig,

    /// Reconnect policy for connection-point DIDComm links
    #[serde(default)]
    pub reconnect_policy: ReconnectPolicyConfig,

    /// Logging configuration
    #[serde(default)]
    pub logging: LoggingConfig,

    /// Extension inspection configuration
    #[serde(default)]
    pub extension_inspection: ExtensionInspectionConfig,

    /// RBAC (Role-Based Access Control) configuration
    #[serde(default)]
    pub rbac: crate::rbac::RbacConfig,

    /// DID document cache configuration for resilient gateway communication
    #[serde(default)]
    pub did_cache: DIDCacheBootstrapConfig,

    /// Configuration file paths (all JSON config files)
    #[serde(default)]
    pub config_files: ConfigFilePaths,

    /// Storage paths (all directories where data is persisted)
    #[serde(default)]
    pub storage_paths: StoragePaths,

    /// Secrets backend type (filesystem or aws)
    #[serde(default = "default_secrets_backend")]
    pub secrets_backend: String,

    /// Cache TTL for metrics aggregations in seconds (default: 1)
    #[serde(default = "default_metrics_cache_ttl")]
    pub metrics_cache_ttl_seconds: u64,

    /// Require authentication for WebSocket connections (default: true)
    #[serde(default = "default_true")]
    pub websocket_require_auth: bool,

    /// Session timeout in minutes (applies to both passkey and SAML)
    #[serde(default = "default_session_timeout_minutes")]
    pub session_timeout_minutes: u64,

    /// WebSocket broadcast channel buffer size (default: 500)
    #[serde(default = "default_websocket_broadcast_buffer")]
    pub websocket_broadcast_buffer: usize,

    /// How long to keep metrics in minutes (default: 360 = 6 hours)
    #[serde(default = "default_metrics_retention_minutes")]
    pub metrics_retention_minutes: u64,

    /// Cache TTL for metrics aggregations in seconds (default: 1)
    #[serde(default = "default_metrics_cache_ttl")]
    pub metrics_cache_ttl_seconds_legacy: u64,

    /// Authentication mode (passkey or saml)
    #[serde(default)]
    pub auth_mode: crate::auth::auth_config::AuthMode,

    /// Backup encryption key (REQUIRED). Sourced at runtime: an `env://VAR` reference
    /// (recommended), a literal 64-char hex string (= 32-byte AES-256 key), or a
    /// `file://path` reference. `aws_secrets://` / `aws_parameter_store://` are not
    /// supported. Absent from config = a parse error; empty or unresolvable = the
    /// service fails to start.
    pub backup_encryption_key: String,

    /// Optional source resolving to up to four ordered, comma-separated previous backup keys.
    #[serde(default)]
    pub legacy_backup_encryption_keys: Option<String>,

    /// Trust Registry runtime tunables (Q3 resource name toggle etc.).
    #[serde(default)]
    pub trust_registry: TrustRegistryRuntimeConfig,

    /// Tenancy hardening. `tenancy.trusted_tenant_header` opts in to honoring a
    /// broad PAT tenant selector because an edge-authenticated proxy owns the
    /// tenant header. Absent by default: broad selectors fail closed.
    #[serde(default)]
    pub tenancy: crate::tenancy::TenancyConfig,

    /// Directory the bootstrap config.toml was loaded from. Populated
    /// by `BootstrapConfig::from_file` and used by services that need
    /// to resolve sibling resource folders (e.g. the agent surface
    /// template seeder scanning `<config_dir>/agent_surface_templates`).
    #[serde(skip)]
    pub config_dir: Option<PathBuf>,

    /// Initial server mode on startup: `active` (default) or `standby`.
    /// Send SIGUSR1 to promote to active, SIGUSR2 to step down to standby.
    #[serde(default)]
    pub server_mode: crate::server::mode::ServerMode,

    /// Interval, in seconds, at which cached filesystem stores reconcile their
    /// in-memory cache with disk. `0` (default) disables periodic refresh, for
    /// single-node deployments that own their storage. Set a positive value for
    /// shared-storage deployments so a standby node tails the active writer and
    /// serves fresh state the moment it is promoted.
    #[serde(default)]
    pub cache_refresh_interval_secs: u64,
}

/// DID document cache configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DIDCacheBootstrapConfig {
    /// Time-to-live for DID cache entries in seconds (default: 3600 = 1 hour)
    #[serde(default = "default_did_cache_ttl_seconds")]
    pub ttl_seconds: i64,

    /// Maximum number of entries in the DID cache (default: 1000)
    #[serde(default = "default_did_cache_max_entries")]
    pub max_entries: usize,

    /// Percentage of TTL after which entries are considered stale (default: 80%)
    #[serde(default = "default_did_cache_stale_threshold_percent")]
    pub stale_threshold_percent: u8,

    /// Path to store cached DID documents (default: _storage/cache/did)
    #[serde(default = "default_did_cache_storage_path")]
    pub storage_path: String,

    /// Let did:web and did:webvh resolution contact hosts that are, or resolve
    /// to, loopback, private-network or link-local addresses, cloud metadata
    /// included, plus the local names each method refuses (default: false,
    /// public hosts only). Startup-only; meant for local stacks.
    #[serde(default)]
    pub allow_private_hosts: bool,
}

impl Default for DIDCacheBootstrapConfig {
    fn default() -> Self {
        Self {
            ttl_seconds: default_did_cache_ttl_seconds(),
            max_entries: default_did_cache_max_entries(),
            stale_threshold_percent: default_did_cache_stale_threshold_percent(),
            storage_path: default_did_cache_storage_path(),
            allow_private_hosts: false,
        }
    }
}

/// Trust Registry runtime tunables.
///
/// Currently exposes a single knob:
/// [`TrustRegistryRuntimeConfig::q3_resource_name`] — the wire resource string
/// sent on Q3 recognition queries (Authority-recognises-Issuer) and used when
/// registering / deregistering an Issuer under an Authority. Historically the
/// value was `"registeredDepartment"`, matching the pre-rename terminology;
/// after the `department` → `issuer` rename the canonical value is
/// `"registeredIssuer"`. Existing Trust Registries index records against the
/// legacy string, so the default is left as `"registeredDepartment"` to
/// preserve wire compatibility. Operators whose registries have been updated
/// can flip this to `"registeredIssuer"` per-gateway.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustRegistryRuntimeConfig {
    /// Resource string sent on Q3 recognition queries and on issuer TR
    /// registration/deregistration. Defaults to `"registeredDepartment"`
    /// for wire compatibility with existing Trust Registries; set to
    /// `"registeredIssuer"` once your Trust Registry has been updated.
    #[serde(default = "default_q3_resource_name")]
    pub q3_resource_name: String,
}

impl Default for TrustRegistryRuntimeConfig {
    fn default() -> Self {
        Self {
            q3_resource_name: default_q3_resource_name(),
        }
    }
}

fn default_q3_resource_name() -> String {
    crate::trust_registries::q3_resource_config::LEGACY_Q3_RESOURCE_NAME.to_string()
}

// Default value functions
fn default_channel_config_source() -> String {
    "local".to_string()
}

pub fn default_false() -> bool {
    false
}

/// Default advertised A2A protocol version.
///
/// Mirrors [`crate::a2a::ADVERTISED_VERSION`] so config and the generated cards
/// agree. Operators pin the legacy line by setting `[a2a] default_version = "0.3"`
/// explicitly.
fn default_a2a_version() -> String {
    crate::a2a::ADVERTISED_VERSION.to_string()
}

fn default_mcp_version() -> String {
    "2024-11-05".to_string()
}

fn default_max_body_size() -> usize {
    10 * 1024 * 1024 // 10MB
}

fn default_timeout() -> u64 {
    30
}

fn default_tool_timeout() -> u64 {
    30 // 30 seconds
}

fn default_resource_cache_ttl() -> u64 {
    300 // 5 minutes
}

fn default_fabric_timeout_ms() -> u64 {
    60000 // 60 seconds for fabric gateway requests (allows for slow LLM responses)
}

fn default_message_expires_seconds() -> u64 {
    // Must be strictly greater than default_fabric_timeout_ms (60s) so the
    // mediator does not drop a response while GW1 is still waiting.
    90
}

fn default_max_inflight_dispatches() -> usize {
    256
}

fn default_sdk_inbound_cache_count() -> u32 {
    1024
}

fn default_sdk_inbound_cache_bytes() -> u64 {
    100 * 1024 * 1024 // 100 MiB
}

fn default_log_level() -> String {
    "info".to_string()
}

fn default_identity_storage_path() -> String {
    "_storage/identities".to_string()
}

fn default_vc_keys_path() -> String {
    "_storage/vc_keys".to_string()
}

fn default_metrics_storage_path() -> String {
    "_storage/metrics".to_string()
}

fn default_system_metrics_storage_path() -> String {
    "_storage/system_metrics".to_string()
}

fn default_config_cache_path() -> String {
    "_storage/cache".to_string()
}

fn default_settings_storage_path() -> String {
    "_storage/settings".to_string()
}

fn default_terms_storage_path() -> String {
    "_storage/terms".to_string()
}

fn default_trust_registries_storage_path() -> String {
    "_storage/trust_registries".to_string()
}

fn default_notifications_storage_path() -> String {
    "_storage/notifications".to_string()
}

fn default_notification_templates_storage_path() -> String {
    "_storage/notifications/templates".to_string()
}

fn default_connection_points_storage_path() -> String {
    "_storage/connection_points".to_string()
}

fn default_gateway_config_path() -> String {
    "config/gateway.json".to_string()
}

fn default_payment_policy_path() -> String {
    "config/x402.json".to_string()
}

fn default_x402_proxy_config_path() -> String {
    "config/x402-proxy.json".to_string()
}

#[allow(dead_code)]
fn default_session_timeout_minutes() -> u64 {
    20 // 20 minutes
}

fn default_websocket_broadcast_buffer() -> usize {
    500
}

fn default_metrics_retention_minutes() -> u64 {
    360 // 6 hours
}

fn default_secrets_backend() -> String {
    "filesystem".to_string()
}

fn default_credential_providers_storage_path() -> String {
    "_storage/credential_providers".to_string()
}

fn default_delegation_vault_storage_path() -> String {
    "_storage/delegation_vault".to_string()
}

fn default_agent_surfaces_storage_path() -> String {
    "_storage/agent_surfaces".to_string()
}

fn default_agent_surface_templates_storage_path() -> String {
    "_storage/agent_surface_templates".to_string()
}

fn default_secrets_storage_path() -> String {
    "_storage/secrets".to_string()
}

fn default_apikeys_storage_path() -> String {
    "_storage/apikeys".to_string()
}

fn default_certificates_storage_path() -> String {
    "_storage/certificates".to_string()
}

fn default_mcp_proxies_storage_path() -> String {
    "_storage/mcp_proxies".to_string()
}

fn default_a2a_proxies_storage_path() -> String {
    "_storage/a2a_proxies".to_string()
}

fn default_integrations_storage_path() -> String {
    "_storage/integrations/definitions".to_string()
}

fn default_integration_triggers_storage_path() -> String {
    "_storage/integrations/triggers".to_string()
}

fn default_webhooks_storage_path() -> String {
    "_storage/webhooks".to_string()
}

fn default_gateways_storage_path() -> String {
    "_storage/gateways".to_string()
}

fn default_mediators_storage_path() -> String {
    "_storage/mediators".to_string()
}

fn default_issuers_storage_path() -> String {
    ISSUERS_STORAGE_PATH_DEFAULT.to_string()
}

/// Raw sentinel value for the built-in default `[storage_paths].issuers`.
///
/// Kept as a `const` so callers outside the serde default helper (notably
/// `bootstrap::try_migrate_legacy_issuers_storage_folder`) can detect the
/// "operator did not set the key" case with a byte-for-byte comparison —
/// `storage_paths.issuers` is not resolved to an absolute path, so a
/// resolved comparison would never match.
pub(super) const ISSUERS_STORAGE_PATH_DEFAULT: &str = "_storage/issuers";

fn default_authorities_storage_path() -> String {
    "_storage/authorities".to_string()
}

fn default_messages_storage_path() -> String {
    "_storage/messages".to_string()
}

fn default_x402_transactions_storage_path() -> String {
    "_storage/x402_transactions".to_string()
}

fn default_mpp_transactions_storage_path() -> String {
    "_storage/mpp_transactions".to_string()
}

fn default_sessions_storage_path() -> String {
    "_storage/sessions".to_string()
}

fn default_policy_definitions_storage_path() -> String {
    "_storage/policy_definitions".to_string()
}

fn default_global_policies_storage_path() -> String {
    "_storage/global_policies".to_string()
}

fn default_backup_restore_storage_path() -> String {
    "_backup_restore".to_string()
}

fn default_identity_hash_pepper_file_path() -> String {
    "_storage/identity_hash_pepper".to_string()
}

fn default_metrics_config_path() -> String {
    "config/metrics.json".to_string()
}

fn default_rbac_config_path() -> String {
    "config/rbac.json".to_string()
}

fn default_limits_config_path() -> String {
    "config/limits.json".to_string()
}

fn default_did_cache_ttl_seconds() -> i64 {
    86400 // 24 hours
}

fn default_did_cache_max_entries() -> usize {
    1000
}

fn default_metrics_cache_ttl() -> u64 {
    1
}

fn default_did_cache_stale_threshold_percent() -> u8 {
    80 // 80% of TTL
}

fn default_did_cache_storage_path() -> String {
    "_storage/cache/did".to_string()
}

fn default_test_endpoints_config_path() -> String {
    "config/test-endpoints.json".to_string()
}

fn default_agent_surface_templates_dir() -> String {
    "agent_surface_templates".to_string()
}

/// EVM test endpoint configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvmTestEndpointConfig {
    /// CAIP-2 network identifier (e.g., "eip155:84532" for Base Sepolia)
    pub network: String,

    /// RPC endpoint URL
    pub rpc_endpoint: String,

    /// Token contract address
    pub token_address: String,

    /// Recipient address for test payments
    pub recipient: String,

    /// Amount in token's smallest unit (e.g., "1000000" for 1 USDC with 6 decimals)
    pub amount: String,

    /// Payment method (e.g., "eip3009", "permit2")
    pub payment_method: String,

    /// Token EIP-712 domain name (e.g., "USDC"), issued as `extra.name`; required for EIP-3009
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_name: Option<String>,

    /// Token EIP-712 domain version (e.g., "2"), issued as `extra.version`; required for EIP-3009
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_version: Option<String>,
}

/// Solana test endpoint configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SolanaTestEndpointConfig {
    /// CAIP-2 network identifier (e.g., "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1" for devnet)
    pub network: String,

    /// RPC endpoint URL
    pub rpc_endpoint: String,

    /// Token mint address
    pub token_address: String,

    /// Recipient address for test payments
    pub recipient: String,

    /// Amount in token's smallest unit (e.g., "1000000" for 1 USDC with 6 decimals)
    pub amount: String,
}

/// Test endpoints configuration
/// Provides deployment-specific values for E2E payment testing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestEndpointsConfig {
    /// EVM test endpoint (Base Sepolia by default)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evm: Option<EvmTestEndpointConfig>,

    /// Solana devnet test endpoint
    #[serde(skip_serializing_if = "Option::is_none")]
    pub solana_devnet: Option<SolanaTestEndpointConfig>,

    /// Solana mainnet test endpoint
    #[serde(skip_serializing_if = "Option::is_none")]
    pub solana_mainnet: Option<SolanaTestEndpointConfig>,
}

/// How to inject a DID identity into outgoing requests
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum DidInjectionMode {
    /// Inject DID in X-DID-Identity HTTP header
    #[default]
    Header,
    /// Inject signed DID document in X-DID-Signed-Identity header
    SignedHeader,
    /// Inject DID into protocol-native location (A2A extension, MCP _meta)
    ProtocolNative,
}

/// DID:webvh identity configuration for channels
#[cfg(feature = "didwebvh")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DidWebVhIdentityConfig {
    /// UUID of the DID:webvh identity to use for this channel
    pub identity_id: uuid::Uuid,

    /// Whether to auto-create the identity if it doesn't exist
    #[serde(default)]
    pub auto_create: bool,

    /// Optional DID path override (by default uses identity manager's DID)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub did_path: Option<String>,

    /// How to inject the DID identity into outgoing requests
    #[serde(default)]
    pub injection_mode: DidInjectionMode,
}

#[cfg(test)]
mod did_cache_bootstrap_config_tests {
    use super::DIDCacheBootstrapConfig;

    #[test]
    fn allow_private_hosts_defaults_to_false() {
        let config: DIDCacheBootstrapConfig = toml::from_str("ttl_seconds = 60").unwrap();
        assert!(!config.allow_private_hosts);
        assert!(!DIDCacheBootstrapConfig::default().allow_private_hosts);
    }

    #[test]
    fn allow_private_hosts_parses_true() {
        let config: DIDCacheBootstrapConfig = toml::from_str("allow_private_hosts = true").unwrap();
        assert!(config.allow_private_hosts);
        assert_eq!(config.ttl_seconds, 86400);
    }
}

#[cfg(test)]
mod outbound_config_tests {
    use super::*;
    use serde_json::json;

    // ── validate_outbound_alias ──────────────────────────────────────────────

    #[test]
    fn alias_valid_lowercase() {
        assert!(validate_outbound_alias("partner-a").is_ok());
        assert!(validate_outbound_alias("partner_b").is_ok());
        assert!(validate_outbound_alias("abc123").is_ok());
        assert!(validate_outbound_alias("a").is_ok());
    }

    #[test]
    fn alias_rejects_slash() {
        assert!(validate_outbound_alias("partner/a").is_err());
    }

    #[test]
    fn alias_rejects_space() {
        assert!(validate_outbound_alias("partner a").is_err());
    }

    #[test]
    fn alias_rejects_uppercase() {
        assert!(validate_outbound_alias("PartnerA").is_err());
        assert!(validate_outbound_alias("PARTNER").is_err());
    }

    #[test]
    fn alias_rejects_empty() {
        assert!(validate_outbound_alias("").is_err());
    }

    // ── validate_outbound on AgentSurface ────────────────────────────────────

    fn surface_with_outbound_inner(
        aliases: &[&str],
        listen: Option<&str>,
    ) -> crate::config::agent_surface::AgentSurface {
        let points: Vec<serde_json::Value> = aliases
            .iter()
            .enumerate()
            .map(|(i, a)| {
                json!({
                    "id": format!("tp-{i}"),
                    "name": *a,
                    "alias": *a,
                    "target_endpoint": "https://example.com",
                    "protocol": "a2a",
                    "gateway_url": format!("https://gw.internal:9000/outgoing/test/{}", a),
                    "require_transit_token": false,
                })
            })
            .collect();

        let mut transit = json!({
            "points": points,
            "shared": {},
        });
        if let Some(addr) = listen {
            transit
                .as_object_mut()
                .unwrap()
                .insert("outbound_listen_address".to_string(), json!(addr));
        }

        let surface_json = json!({
            "surface_id": "test-surface",
            "name": "test-channel",
            "description": "Test",
            "status": "active",
            "tags": [],
            "access_point": {
                "listen_address": "0.0.0.0:8443",
                "route": "/",
                "protocol": "a2a",
                "publish_to_did_document": false,
                "supported_extensions": [],
            },
            "target": {
                "endpoint": "http://localhost:9000",
                "mcp_tool_policies": [],
                "mcp_tool_policies_enabled": false,
                "identity_injection": {"inject_vp": false},
            },
            "identity_slots": {},
            "outbound_credentials": [],
            "transit": transit,
        });

        serde_json::from_value(surface_json).expect("surface must deserialize")
    }

    fn surface_with_outbound(
        enabled: bool,
        aliases: &[&str],
    ) -> crate::config::agent_surface::AgentSurface {
        // On AgentSurface, presence of transit points IS the enabled signal.
        // `enabled=false` with non-empty aliases is no longer representable;
        // callers in this test module only pass `enabled=false` with `aliases=&[]`.
        if !enabled {
            assert!(aliases.is_empty(), "surface_with_outbound: disabled state requires empty aliases");
            // Build a surface with no transit block at all.
            let surface_json = json!({
                "surface_id": "test-surface",
                "name": "test-channel",
                "description": "Test",
                "status": "active",
                "tags": [],
                "access_point": {
                    "listen_address": "0.0.0.0:8443",
                    "route": "/",
                    "protocol": "a2a",
                    "publish_to_did_document": false,
                    "supported_extensions": [],
                },
                "target": {
                    "endpoint": "http://localhost:9000",
                    "mcp_tool_policies": [],
                    "mcp_tool_policies_enabled": false,
                    "identity_injection": {"inject_vp": false},
                },
                "identity_slots": {},
                "outbound_credentials": [],
            });
            return serde_json::from_value(surface_json).expect("surface must deserialize");
        }
        surface_with_outbound_inner(aliases, Some("127.0.0.1:9000"))
    }

    #[test]
    fn validate_outbound_enabled_requires_listen_address() {
        let surface = surface_with_outbound_inner(&["partner-a"], None);
        let errors = surface.validate_outbound();
        assert!(!errors.is_empty(), "expected validation error when enabled=true with no listen address");
        assert!(
            errors
                .iter()
                .any(|e: &String| e.contains("outbound_listen_address is not set"))
        );
    }

    #[test]
    fn validate_outbound_accepts_per_transit_point_listen_address() {
        let mut surface = surface_with_outbound_inner(&["partner-a"], None);
        surface
            .transit
            .as_mut()
            .unwrap()
            .points[0]
            .listen_address = Some("https://localhost:9000".to_string());

        assert!(
            surface
                .validate_outbound()
                .is_empty()
        );
    }

    #[test]
    fn validate_outbound_disabled_with_no_channels_is_ok() {
        let surface = surface_with_outbound(false, &[]);
        assert!(
            surface
                .validate_outbound()
                .is_empty()
        );
    }

    #[test]
    fn validate_outbound_enabled_with_channels_is_ok() {
        let surface = surface_with_outbound(true, &["partner-a"]);
        assert!(
            surface
                .validate_outbound()
                .is_empty()
        );
    }

    #[test]
    fn validate_outbound_rejects_duplicate_aliases() {
        let surface = surface_with_outbound(true, &["partner-a", "partner-a"]);
        let errors = surface.validate_outbound();
        assert!(
            errors
                .iter()
                .any(|e: &String| e.contains("not unique"))
        );
    }

    #[test]
    fn validate_outbound_rejects_invalid_alias() {
        let surface = surface_with_outbound(true, &["INVALID"]);
        let errors = surface.validate_outbound();
        assert!(
            errors
                .iter()
                .any(|e: &String| e.contains("lowercase"))
        );
    }

    // ── Listener backward-compat ─────────────────────────────────────────────

    #[test]
    fn listener_without_listener_type_defaults_to_inbound() {
        let v = json!({
            "id": "l1",
            "name": "Main",
            "bind_address": "0.0.0.0",
            "port": 8443,
            "protocol": "https",
            "external_urls": []
        });
        let listener: crate::config::network::Listener =
            serde_json::from_value(v).expect("must deserialize without listener_type");
        assert_eq!(listener.listener_type, "inbound");
    }

    #[test]
    fn listener_with_listener_type_outbound() {
        let v = json!({
            "id": "l2",
            "name": "Outbound",
            "bind_address": "127.0.0.1",
            "port": 9000,
            "protocol": "http",
            "external_urls": [],
            "listener_type": "outbound"
        });
        let listener: crate::config::network::Listener =
            serde_json::from_value(v).expect("must deserialize with listener_type=outbound");
        assert_eq!(listener.listener_type, "outbound");
    }
}

#[cfg(test)]
mod a2a_validate_tests {
    use super::*;

    #[test]
    fn the_deprecated_validate_messages_key_is_still_accepted() {
        let config: A2aConfig = toml::from_str("validate_messages = false").unwrap();
        assert_eq!(config.validate_messages, Some(false));
        assert_eq!(config.validate(), Ok(()));

        let config: A2aConfig = toml::from_str("").unwrap();
        assert_eq!(config.validate_messages, None);
        assert!(
            serde_json::to_value(&config)
                .unwrap()
                .get("validate_messages")
                .is_none(),
            "an unset deprecated key is not written back"
        );
    }

    #[test]
    fn explicit_fabric_stream_envelope_limit_is_bounded_by_range_and_sdk_cache() {
        let mut config: A2aConfig =
            serde_json::from_value(serde_json::json!({"fabric_stream_max_envelope_bytes": 65536})).unwrap();
        assert_eq!(config.fabric_stream_max_envelope_bytes, Some(64 * 1024));
        assert_eq!(serde_json::to_value(&config).unwrap()["fabric_stream_max_envelope_bytes"], 65536);
        for limit in [0, 64 * 1024 - 1, 1024 * 1024 + 1] {
            config.fabric_stream_max_envelope_bytes = Some(limit);
            assert!(
                config
                    .validate()
                    .unwrap_err()
                    .contains("fabric_stream_max_envelope_bytes")
            );
        }
        for limit in [64 * 1024, 1024 * 1024] {
            config.fabric_stream_max_envelope_bytes = Some(limit);
            assert_eq!(config.validate(), Ok(()));
            assert_eq!(config.stream_envelope_limit(), limit);
        }
        config.fabric_stream_max_envelope_bytes = Some(128 * 1024);
        config.sdk_inbound_cache_bytes = 128 * 1024 - 1;
        assert!(config.validate().is_err());
        config.sdk_inbound_cache_bytes = 128 * 1024;
        assert_eq!(config.validate(), Ok(()));
    }

    #[test]
    fn unset_fabric_stream_envelope_limit_follows_the_sdk_cache_and_always_validates() {
        let config: A2aConfig = serde_json::from_value(serde_json::json!({})).unwrap();
        assert_eq!(config.fabric_stream_max_envelope_bytes, None);
        assert_eq!(config.stream_envelope_limit(), 128 * 1024);
        assert_eq!(config.validate(), Ok(()));
        assert!(
            serde_json::to_value(&config)
                .unwrap()
                .get("fabric_stream_max_envelope_bytes")
                .is_none()
        );
        for (cache, limit) in [(64 * 1024, 64 * 1024), (1024, 1024), (128 * 1024, 128 * 1024), (u64::MAX, 128 * 1024)] {
            let config = A2aConfig {
                sdk_inbound_cache_bytes: cache,
                ..A2aConfig::default()
            };
            assert_eq!(config.validate(), Ok(()), "cache {cache}");
            assert_eq!(config.stream_envelope_limit(), limit, "cache {cache}");
        }
    }

    fn cfg(
        timeout_ms: u64,
        expires_s: u64,
    ) -> A2aConfig {
        A2aConfig {
            fabric_gateway_timeout_ms: timeout_ms,
            message_expires_seconds: expires_s,
            ..A2aConfig::default()
        }
    }

    /// `default_version` is advertised in generated cards, so an unrecognised
    /// value must be refused at startup rather than published to clients.
    #[test]
    fn validate_rejects_an_unsupported_default_version() {
        for bad in ["2.0", "0.2", "banana", ""] {
            let c = A2aConfig {
                default_version: bad.to_string(),
                ..A2aConfig::default()
            };
            let err = c
                .validate()
                .expect_err("{bad} must be refused");
            assert!(err.contains("a2a.default_version"), "error should name the setting, got: {err}");
            assert!(err.contains("supported"), "error should list what is supported, got: {err}");
        }
    }

    #[test]
    fn default_version_is_1_0_when_not_configured() {
        assert_eq!(A2aConfig::default().default_version, "1.0");

        let from_empty_table: A2aConfig = toml::from_str("").expect("an empty [a2a] table must deserialize");
        assert_eq!(from_empty_table.default_version, "1.0");
        assert!(
            from_empty_table
                .validate()
                .is_ok()
        );
    }

    #[test]
    fn configured_default_version_is_kept_as_written() {
        let pinned: A2aConfig = toml::from_str(r#"default_version = "0.3""#).expect("must deserialize");
        assert_eq!(pinned.default_version, "0.3");
        assert!(pinned.validate().is_ok());
    }

    #[test]
    fn validate_accepts_either_supported_version_and_a_patch_suffix() {
        for good in ["1.0", "0.3", "1.0.1"] {
            let c = A2aConfig {
                default_version: good.to_string(),
                ..A2aConfig::default()
            };
            assert!(c.validate().is_ok(), "{good} should be accepted");
        }
    }

    #[test]
    fn validate_ok_when_expires_strictly_greater_than_timeout() {
        let c = cfg(60_000, 90);
        assert!(c.validate().is_ok());
    }

    #[test]
    fn validate_rejects_equal_values() {
        let c = cfg(60_000, 60);
        let err = c.validate().unwrap_err();
        assert!(err.contains("strictly greater"), "got: {err}");
    }

    #[test]
    fn validate_rejects_expires_less_than_timeout() {
        let c = cfg(60_000, 30);
        assert!(c.validate().is_err());
    }

    #[test]
    fn validate_rejects_zero_inflight() {
        let mut c = cfg(60_000, 90);
        c.max_inflight_dispatches = 0;
        let err = c.validate().unwrap_err();
        assert!(err.contains("max_inflight_dispatches"), "got: {err}");
    }

    #[test]
    fn validate_rejects_zero_sdk_cache_bytes_or_count() {
        let mut c = cfg(60_000, 90);
        c.sdk_inbound_cache_count = 0;
        assert!(c.validate().is_err());
        let mut c = cfg(60_000, 90);
        c.sdk_inbound_cache_bytes = 0;
        assert!(c.validate().is_err());
    }

    #[test]
    fn validate_handles_overflow_via_saturating_mul() {
        // huge expires must not panic
        let c = cfg(u64::MAX, u64::MAX);
        // With saturating arithmetic, expires_ms saturates to u128::MAX which
        // exceeds any u64 timeout, so this must succeed.
        assert!(c.validate().is_ok());
    }

    #[test]
    fn defaults_satisfy_validate() {
        assert!(
            A2aConfig::default()
                .validate()
                .is_ok()
        );
    }
}

#[cfg(test)]
mod unresolved_outbound_tests {
    use super::*;
    use serde_json::json;

    fn surface_with_transit(value: serde_json::Value) -> crate::config::agent_surface::AgentSurface {
        serde_json::from_value(value).expect("test surface must deserialize")
    }

    /// Resolver standing in for the outbound-restricted `map_url_to_port_for_type`:
    /// only `https://out.example.com` belongs to an outbound listener (port 8081).
    fn outbound_resolver(addr: &str) -> Option<u16> {
        if addr == "https://out.example.com" {
            Some(8081)
        } else {
            None
        }
    }

    #[test]
    fn all_points_resolve_returns_empty() {
        let surface = surface_with_transit(json!({
            "name": "S1",
            "status": "active",
            "access_point": { "listen_address": "https://in.example.com", "route": "/x", "protocol": "a2a" },
            "target": { "endpoint": "http://localhost:1/x" },
            "transit": {
                "outbound_listen_address": "https://out.example.com",
                "points": [
                    { "alias": "tp1", "target_endpoint": "http://localhost:2", "listen_address": "https://out.example.com" }
                ]
            }
        }));

        let problems = find_unresolved_outbound_transit_points(&[surface], &[8081], outbound_resolver);
        assert!(problems.is_empty(), "expected no problems, got: {problems:?}");
    }

    #[test]
    fn address_only_on_inbound_listener_is_unresolved() {
        // Transit point points at the inbound URL, which the outbound resolver ignores.
        let surface = surface_with_transit(json!({
            "name": "S1",
            "status": "active",
            "access_point": { "listen_address": "https://in.example.com", "route": "/x", "protocol": "a2a" },
            "target": { "endpoint": "http://localhost:1/x" },
            "transit": {
                "points": [
                    { "alias": "tp1", "target_endpoint": "http://localhost:2", "listen_address": "https://in.example.com" }
                ]
            }
        }));

        let problems = find_unresolved_outbound_transit_points(&[surface], &[8081], outbound_resolver);
        assert_eq!(problems.len(), 1);
        assert_eq!(problems[0].surface_name, "S1");
        assert_eq!(problems[0].alias, "tp1");
        assert_eq!(
            problems[0]
                .listen_address
                .as_deref(),
            Some("https://in.example.com")
        );
        assert!(
            problems[0]
                .reason
                .contains("not in the external_urls of any outbound listener"),
            "got: {}",
            problems[0].reason
        );
    }

    #[test]
    fn missing_address_is_unresolved() {
        // Neither the transit point nor the surface declares an outbound listen address.
        let surface = surface_with_transit(json!({
            "name": "S2",
            "status": "active",
            "access_point": { "listen_address": "https://in.example.com", "route": "/x", "protocol": "a2a" },
            "target": { "endpoint": "http://localhost:1/x" },
            "transit": {
                "points": [
                    { "alias": "tp1", "target_endpoint": "http://localhost:2" }
                ]
            }
        }));

        let problems = find_unresolved_outbound_transit_points(&[surface], &[8081], outbound_resolver);
        assert_eq!(problems.len(), 1);
        assert_eq!(problems[0].listen_address, None);
        assert!(
            problems[0]
                .reason
                .contains("no outbound listen address"),
            "got: {}",
            problems[0].reason
        );
    }

    #[test]
    fn point_inherits_surface_address_when_set() {
        // Transit point has no listen_address but the surface default resolves.
        let surface = surface_with_transit(json!({
            "name": "S3",
            "status": "active",
            "access_point": { "listen_address": "https://in.example.com", "route": "/x", "protocol": "a2a" },
            "target": { "endpoint": "http://localhost:1/x" },
            "transit": {
                "outbound_listen_address": "https://out.example.com",
                "points": [
                    { "alias": "tp1", "target_endpoint": "http://localhost:2" }
                ]
            }
        }));

        let problems = find_unresolved_outbound_transit_points(&[surface], &[8081], outbound_resolver);
        assert!(problems.is_empty(), "expected inheritance to resolve, got: {problems:?}");
    }

    #[test]
    fn disabled_surface_is_skipped() {
        let surface = surface_with_transit(json!({
            "name": "S4",
            "status": "disabled",
            "access_point": { "listen_address": "https://in.example.com", "route": "/x", "protocol": "a2a" },
            "target": { "endpoint": "http://localhost:1/x" },
            "transit": {
                "points": [
                    { "alias": "tp1", "target_endpoint": "http://localhost:2", "listen_address": "https://in.example.com" }
                ]
            }
        }));

        let problems = find_unresolved_outbound_transit_points(&[surface], &[8081], outbound_resolver);
        assert!(problems.is_empty(), "disabled surfaces must be ignored, got: {problems:?}");
    }
}

#[cfg(test)]
mod workload_binding_config_tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn workload_binding_serializes_caller_context_fields_as_string_list() {
        let wb = WorkloadBindingConfig {
            enabled: true,
            caller_source: CallerContextSource::TransitToken,
            caller_context_fields: vec!["sub".into(), "email".into()],
            ..Default::default()
        };
        let v = serde_json::to_value(&wb).unwrap();
        assert_eq!(v["caller_context_fields"], json!(["sub", "email"]));
        assert_eq!(v["enabled"], json!(true));
        assert_eq!(v["caller_source"], json!("transit_token"));
    }

    #[test]
    fn workload_binding_omits_empty_caller_context_fields() {
        let wb = WorkloadBindingConfig::default();
        let v = serde_json::to_value(&wb).unwrap();
        assert!(
            v.get("caller_context_fields")
                .is_none(),
            "empty allowlist must be omitted from the wire shape"
        );
    }

    #[test]
    fn workload_binding_parses_transit_token_source() {
        let wb: WorkloadBindingConfig = serde_json::from_value(json!({
            "enabled": true,
            "caller_source": "transit_token",
            "caller_context_fields": ["sub"]
        }))
        .unwrap();
        assert_eq!(wb.caller_source, CallerContextSource::TransitToken);
        assert!(wb.enabled);
    }

    #[test]
    fn workload_binding_parses_authorization_bearer_jwt_source() {
        let wb: WorkloadBindingConfig = serde_json::from_value(json!({
            "caller_source": "authorization_bearer_jwt"
        }))
        .unwrap();
        assert_eq!(wb.caller_source, CallerContextSource::AuthorizationBearerJwt);
    }

    #[test]
    fn workload_binding_parses_did_source() {
        let wb: WorkloadBindingConfig = serde_json::from_value(json!({
            "enabled": true,
            "caller_source": "did"
        }))
        .unwrap();
        assert_eq!(wb.caller_source, CallerContextSource::Did);
        assert!(wb.enabled);
        let back = serde_json::to_value(&wb).unwrap();
        assert_eq!(back["caller_source"], "did");
    }

    #[test]
    fn workload_binding_caller_source_defaults_to_transit_token() {
        let wb: WorkloadBindingConfig = serde_json::from_value(json!({})).unwrap();
        assert_eq!(wb.caller_source, CallerContextSource::TransitToken);
    }

    #[test]
    fn workload_binding_accepts_arbitrary_allowlisted_claim_names() {
        let wb: WorkloadBindingConfig = serde_json::from_value(json!({
            "caller_context_fields": ["sub", "custom_org_claim", "role"]
        }))
        .unwrap();
        assert!(wb.validate().is_ok());
        assert_eq!(wb.caller_context_fields.len(), 3);
    }

    #[test]
    fn workload_binding_rejects_alias_mapping_object_in_caller_context_fields() {
        let res: Result<WorkloadBindingConfig, _> = serde_json::from_value(json!({
            "caller_context_fields": [{ "claim": "sub", "output_name": "subject" }]
        }));
        assert!(res.is_err(), "aliasing objects must not deserialize into a plain string list");
    }

    #[test]
    fn workload_binding_rejects_mask_configuration_in_caller_context_fields() {
        let res: Result<WorkloadBindingConfig, _> = serde_json::from_value(json!({
            "caller_context_fields": [{ "claim": "email", "mask": "email" }]
        }));
        assert!(res.is_err(), "mask configuration must not be accepted on caller_context_fields");
    }

    #[test]
    fn workload_binding_rejects_nested_path_syntax() {
        let wb: WorkloadBindingConfig = serde_json::from_value(json!({
            "caller_context_fields": ["profile.email"]
        }))
        .unwrap();
        assert_eq!(wb.validate().unwrap_err(), WorkloadBindingValidationError::Nested { name: "profile.email".into() });
    }

    #[test]
    fn workload_binding_rejects_blank_claim() {
        let wb: WorkloadBindingConfig = serde_json::from_value(json!({
            "caller_context_fields": ["  "]
        }))
        .unwrap();
        assert_eq!(wb.validate().unwrap_err(), WorkloadBindingValidationError::Blank);
    }

    #[test]
    fn workload_binding_rejects_duplicate_claim() {
        let wb = WorkloadBindingConfig {
            caller_context_fields: vec!["sub".into(), "sub".into()],
            ..Default::default()
        };
        assert_eq!(wb.validate().unwrap_err(), WorkloadBindingValidationError::Duplicate { name: "sub".into() });
    }

    #[test]
    fn workload_binding_round_trips_caller_credential_chaining() {
        let wb = WorkloadBindingConfig {
            enabled: true,
            chain_caller_credentials: true,
            caller_context_fields: vec!["sub".into()],
            ..Default::default()
        };
        let json = serde_json::to_string(&wb).unwrap();
        let back: WorkloadBindingConfig = serde_json::from_str(&json).unwrap();
        assert!(back.chain_caller_credentials);
        assert!(back.enabled);
        assert!(back.validate().is_ok());
    }

    #[test]
    fn workload_binding_bind_request_defaults_true() {
        let wb: WorkloadBindingConfig = serde_json::from_value(json!({})).unwrap();
        assert!(wb.bind_request, "bind_request must default to true");
    }

    /// Compat: legacy operator configs use `[storage_paths].departments`; the
    /// serde alias must accept it and expose the value on the canonical
    /// `issuers` field.
    #[test]
    fn storage_paths_accepts_legacy_departments_key() {
        let toml_body = r#"departments = "/custom/legacy-path""#;
        let sp: StoragePaths = toml::from_str(toml_body).expect("legacy `departments` key must deserialize");
        assert_eq!(sp.issuers, "/custom/legacy-path");
    }

    /// Compat: when only the canonical key is set, its value is used verbatim
    /// (regression pin for the serde alias not accidentally shadowing the
    /// canonical field with a default when the operator has already migrated).
    #[test]
    fn storage_paths_uses_canonical_issuers_key_verbatim() {
        let toml_body = r#"issuers = "/canonical/path""#;
        let sp: StoragePaths = toml::from_str(toml_body).expect("canonical `issuers` key must deserialize");
        assert_eq!(sp.issuers, "/canonical/path");
    }
}

#[cfg(test)]
mod x402_storage_config_tests {
    use super::*;
    use serde_json::json;

    fn settlement_worker_settings(config: &X402Config) -> (usize, u64, u32) {
        let storage = config
            .settlement_storage
            .as_ref()
            .expect("settlement_storage configured");
        (storage.batch_size, storage.settlement_interval_seconds, storage.max_retries)
    }

    #[test]
    fn example_x402_config_parses_settlement_worker_settings() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("config/examples/x402.example.json");
        let contents = std::fs::read_to_string(path).expect("read x402 example");
        let config: X402Config = serde_json::from_str(&contents).expect("parse x402 example");

        assert_eq!(settlement_worker_settings(&config), (100, 60, 3));
        assert!(
            config
                .transaction_storage
                .is_none()
        );
    }

    #[test]
    fn legacy_storage_keys_are_ignored_and_live_settings_still_apply() {
        let config: X402Config = serde_json::from_value(json!({
            "settlement_storage": {
                "backend": "dynamodb",
                "filesystem_path": "./storage/x402_payments",
                "dynamodb_table": "x402_payments",
                "dynamodb_region": "us-east-1",
                "dynamodb_profile": "default",
                "retention_days": 90,
                "max_memory_records": 10000,
                "batch_size": 25,
                "settlement_interval_seconds": 15,
                "max_retries": 5
            },
            "verification_storage": {"backend": "dynamodb", "dynamodb_table": "x402_verifications"},
            "transaction_storage": {
                "backend": "dynamodb",
                "dynamodb_table": "x402_transactions",
                "filesystem_path": "/data/x402-transactions",
                "retention_days": 30
            }
        }))
        .expect("legacy keys parse");

        assert_eq!(settlement_worker_settings(&config), (25, 15, 5));
        assert_eq!(
            config.transaction_storage,
            Some(X402TransactionStorageConfig {
                filesystem_path: "/data/x402-transactions".to_string(),
                retention_days: 30,
            })
        );
    }

    #[test]
    fn empty_storage_sections_use_defaults() {
        let config: X402Config =
            serde_json::from_value(json!({"settlement_storage": {}, "transaction_storage": {}})).expect("parse");

        assert_eq!(settlement_worker_settings(&config), (100, 60, 3));
        assert_eq!(config.transaction_storage, Some(X402TransactionStorageConfig::default()));
        assert_eq!(
            X402TransactionStorageConfig::default(),
            X402TransactionStorageConfig {
                filesystem_path: "_storage/x402-transactions".to_string(),
                retention_days: 7,
            }
        );
    }

    #[test]
    fn missing_settlement_storage_leaves_worker_unconfigured() {
        let config: X402Config = serde_json::from_value(json!({})).expect("parse");

        assert!(
            config
                .settlement_storage
                .is_none()
        );
        assert!(
            config
                .transaction_storage
                .is_none()
        );
    }

    #[test]
    fn invalid_settlement_worker_setting_is_rejected() {
        let err = serde_json::from_value::<X402Config>(json!({"settlement_storage": {"batch_size": "many"}}))
            .expect_err("non-numeric batch_size must fail");

        assert!(
            err.to_string()
                .contains("invalid type"),
            "unexpected error: {err}"
        );
    }
}
