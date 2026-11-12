use anyhow::{Context, Result, anyhow};
use async_trait::async_trait;
use aws_sdk_dynamodb::Client as DynamoDbClient;
use std::collections::HashMap;
use std::sync::Mutex;
use tracing::{debug, info, warn};

use crate::config::{
    A2aConfig, ExtensionInspectionConfig, GatewayConfig, IntegrationConfig, LoggingConfig, McpConfig, TlsConfig,
};
use crate::storage::ConfigurationStore;

/// Warnings raised while an item is parsed. The gateway reads its DynamoDB
/// configuration before it installs its log subscriber, so a warning raised
/// then is held until [`start_logging_warnings`] and logged at once afterwards.
#[derive(Default)]
struct DeferredWarnings {
    started: bool,
    pending: Vec<String>,
}

impl DeferredWarnings {
    /// Holds `message` until logging starts, or hands it back to log now.
    fn record(
        &mut self,
        message: String,
    ) -> Option<String> {
        if self.started {
            Some(message)
        } else {
            self.pending.push(message);
            None
        }
    }

    /// Marks logging as started and returns the held messages, oldest first.
    fn start(&mut self) -> Vec<String> {
        self.started = true;
        std::mem::take(&mut self.pending)
    }
}

static DEFERRED_WARNINGS: Mutex<DeferredWarnings> = Mutex::new(DeferredWarnings {
    started: false,
    pending: Vec::new(),
});

fn warn_when_logging(message: String) {
    let now = DEFERRED_WARNINGS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .record(message);
    if let Some(message) = now {
        warn!("{message}");
    }
}

/// Logs the warnings held while the DynamoDB configuration was read, and logs
/// later ones at once. Call it right after the log subscriber is installed.
pub fn start_logging_warnings() {
    let held = DEFERRED_WARNINGS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .start();
    for message in held {
        warn!("{message}");
    }
}

/// The type of an ignored `public` attribute's value; its content is never logged.
fn describe_attribute(value: &aws_sdk_dynamodb::types::AttributeValue) -> &'static str {
    use aws_sdk_dynamodb::types::AttributeValue;
    match value {
        AttributeValue::S(_) => "string",
        AttributeValue::N(_) => "number",
        AttributeValue::Null(_) => "null",
        AttributeValue::M(_) => "map",
        AttributeValue::L(_) => "list",
        AttributeValue::B(_) => "binary value",
        AttributeValue::Ss(_) | AttributeValue::Ns(_) | AttributeValue::Bs(_) => "set",
        _ => "value of an unsupported type",
    }
}

/// The warning for a `public` attribute of item `config_id` that holds `value`.
fn ignored_public_message(
    config_id: &str,
    value: &aws_sdk_dynamodb::types::AttributeValue,
) -> String {
    format!(
        "Ignoring the DynamoDB channel attribute 'public' of item '{config_id}': found {}, expected a boolean, or the \
         string 'true' or 'false'; the surface keeps no Public access setting",
        describe_attribute(value)
    )
}

/// DynamoDB-based configuration store
///
/// Expected DynamoDB table schema:
/// - Partition Key: `config_type` (String) - e.g., "channel", "tls", "a2a", "logging"
/// - Sort Key: `config_id` (String) - e.g., channel name, or "default" for singleton configs
///
/// Attributes depend on config_type:
/// - For channels: name, description, listen_address, target_endpoint, managed_identity (with extension_rules for identity schema),
///   and an optional boolean `public` (`access_point.public`)
/// - For tls: cert_path, key_path, verify_upstream
/// - For a2a: default_version, max_body_size, timeout_seconds
/// - For logging: level, json
pub struct DynamoDbConfigStore {
    client: DynamoDbClient,
    table_name: String,
}

impl DynamoDbConfigStore {
    /// Create a new DynamoDB configuration store
    pub async fn new(
        table_name: String,
        region: Option<String>,
        profile: Option<String>,
    ) -> Result<Self> {
        debug!("Initializing DynamoDB configuration store");
        debug!("Loading AWS credentials from default credential chain");
        debug!("  Checking: environment variables, ~/.aws/credentials, ~/.aws/config (SSO), IAM roles");

        // Load AWS configuration from environment with Tokio sleep implementation
        // This includes credentials from environment variables, AWS credentials file, SSO, and IAM roles
        let mut config_loader = aws_config::defaults(aws_config::BehaviorVersion::latest())
            .sleep_impl(std::sync::Arc::new(aws_smithy_async::rt::sleep::TokioSleep::new()));

        // Set profile if provided
        if let Some(ref profile_name) = profile {
            debug!("Using AWS profile from bootstrap config: {}", profile_name);
            config_loader = config_loader.profile_name(profile_name);
        } else {
            debug!("No profile specified in bootstrap config, using default profile or environment credentials");
        }

        // Set region if provided
        if let Some(ref region_str) = region {
            debug!("Using AWS region from bootstrap config: {}", region_str);
            config_loader = config_loader.region(aws_config::Region::new(region_str.clone()));
        } else {
            debug!("No region specified in bootstrap config, using default from credential chain");
        }

        let config = config_loader.load().await;

        let client = DynamoDbClient::new(&config);

        debug!("DynamoDB client initialized for table: {}", table_name);
        debug!("Note: If you see 'no providers in chain provided credentials', ensure:");
        debug!("  1. AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY are set, OR");
        debug!("  2. ~/.aws/credentials file exists with valid credentials, OR");
        debug!("  3. AWS SSO is configured and you've run 'aws sso login', OR");
        debug!("  4. Running on AWS infrastructure (EC2/ECS/Lambda) with IAM role");

        Ok(Self { client, table_name })
    }

    /// Load channel configurations from DynamoDB
    async fn load_channels(&self) -> Result<Vec<crate::config::agent_surface::AgentSurface>> {
        debug!("Loading channels from DynamoDB");

        let result = self
            .client
            .query()
            .table_name(&self.table_name)
            .key_condition_expression("config_type = :config_type")
            .expression_attribute_values(
                ":config_type",
                aws_sdk_dynamodb::types::AttributeValue::S("channel".to_string()),
            )
            .send()
            .await
            .context("Failed to query channels from DynamoDB")?;

        let mut channels = Vec::new();

        if let Some(items) = result.items {
            for item in items {
                let surface = self.parse_channel_item(item)?;
                // Only include channels that are not marked as deleted
                if surface.status != crate::config::agent_surface::SurfaceStatus::Deleted {
                    channels.push(surface);
                }
            }
        }

        if channels.is_empty() {
            warn!("No active channels found in DynamoDB table");
        }

        info!("Loaded {} channel(s) from DynamoDB", channels.len());
        Ok(channels)
    }

    /// Load a single channel by config_id from DynamoDB
    pub async fn load_single_channel_by_config_id(
        &self,
        config_id: &str,
    ) -> Result<crate::config::agent_surface::AgentSurface> {
        debug!("Loading channel with config_id '{}' from DynamoDB", config_id);

        // Query directly using config_id as sort key
        let result = self
            .client
            .get_item()
            .table_name(&self.table_name)
            .key("config_type", aws_sdk_dynamodb::types::AttributeValue::S("channel".to_string()))
            .key("config_id", aws_sdk_dynamodb::types::AttributeValue::S(config_id.to_string()))
            .send()
            .await
            .context("Failed to get channel by config_id from DynamoDB")?;

        if let Some(item) = result.item {
            let surface = self.parse_channel_item(item)?;
            debug!("Successfully loaded channel with config_id '{}' from DynamoDB", config_id);
            Ok(surface)
        } else {
            anyhow::bail!("Channel with config_id '{}' not found in DynamoDB table", config_id)
        }
    }

    fn parse_channel_protocol(
        item: &HashMap<String, aws_sdk_dynamodb::types::AttributeValue>
    ) -> Result<crate::config::ChannelProtocol> {
        match item.get("protocol") {
            None => Ok(crate::config::ChannelProtocol::A2a),
            Some(value) => {
                let protocol = value
                    .as_s()
                    .map_err(|_| anyhow!("Invalid protocol attribute type: expected string"))?;
                serde_json::from_value(serde_json::Value::String(protocol.to_string()))
                    .with_context(|| format!("Invalid protocol value: {}", protocol))
            }
        }
    }

    /// The item's `public` attribute, the surface's `access_point.public`: a
    /// boolean, or the string `"true"` or `"false"`. `None` when it has none,
    /// a legacy surface; any other value is logged and ignored.
    fn parse_public(item: &HashMap<String, aws_sdk_dynamodb::types::AttributeValue>) -> Option<bool> {
        use aws_sdk_dynamodb::types::AttributeValue;
        let value = item.get("public")?;
        let public = match value {
            AttributeValue::Bool(public) => Some(*public),
            AttributeValue::S(text) if text == "true" => Some(true),
            AttributeValue::S(text) if text == "false" => Some(false),
            _ => None,
        };
        if public.is_none() {
            let config_id = item
                .get("config_id")
                .and_then(|v| v.as_s().ok())
                .map_or("", String::as_str);
            warn_when_logging(ignored_public_message(config_id, value));
        }
        public
    }

    /// Parse a DynamoDB item into an AgentSurface
    fn parse_channel_item(
        &self,
        item: HashMap<String, aws_sdk_dynamodb::types::AttributeValue>,
    ) -> Result<crate::config::agent_surface::AgentSurface> {
        let config_id = item
            .get("config_id")
            .and_then(|v| v.as_s().ok())
            .map(|s| s.to_string());
        let name = self.get_string_attribute(&item, "name")?;
        let description = self.get_string_attribute(&item, "description")?;
        let listen_address = self.get_string_attribute(&item, "listen_address")?;
        let target_endpoint = self.get_string_attribute(&item, "target_endpoint")?;

        // Get route (default to "/" if not specified for backward compatibility)
        let route = self
            .get_string_attribute(&item, "route")
            .unwrap_or_else(|_| "/".to_string());

        // Get custom_metadata if present
        let custom_metadata = item
            .get("custom_metadata")
            .and_then(|v| v.as_s().ok())
            .and_then(|s| serde_json::from_str(s).ok());

        // Get channel_type if present, default to User
        let channel_type = item
            .get("channel_type")
            .and_then(|v| v.as_s().ok())
            .and_then(|s| serde_json::from_str(&format!(r#""{}""#, s)).ok())
            .unwrap_or(crate::config::SurfaceType::User);

        // Missing protocol defaults to A2a; explicit invalid values fail parsing.
        let protocol = Self::parse_channel_protocol(&item)?;

        // Get fabric_target_name if present (optional)
        let fabric_target_name = item
            .get("fabric_target_name")
            .and_then(|v| v.as_s().ok())
            .map(|s| s.to_string());

        // Get opa_enabled if present, default to false
        let opa_enabled = item
            .get("opa_enabled")
            .and_then(|v| v.as_bool().ok().copied())
            .unwrap_or(false);

        // Get source_auth if present
        let source_auth: Option<crate::source_auth::SourceAuthConfig> = item
            .get("source_auth")
            .and_then(|v| v.as_s().ok())
            .and_then(|s| serde_json::from_str(s).ok());

        // Get managed_identity if present
        let managed_identity: Option<crate::source_auth::ManagedIdentityConfig> = item
            .get("managed_identity")
            .and_then(|v| v.as_s().ok())
            .and_then(|s| serde_json::from_str(s).ok());

        let target_auth: Option<crate::config::types::TargetAuthConfig> = item
            .get("target_auth")
            .and_then(|v| v.as_s().ok())
            .and_then(|s| serde_json::from_str(s).ok());

        use crate::config::agent_surface::{
            AccessPoint, AgentSurface, CallerAuthentication, SurfaceIdentitySlots, SurfaceProtocol, SurfaceStatus,
            Target,
        };

        let surface_protocol = match protocol {
            crate::config::ChannelProtocol::A2a => SurfaceProtocol::A2a,
            crate::config::ChannelProtocol::Ap2 => SurfaceProtocol::Ap2,
            crate::config::ChannelProtocol::Mcp => SurfaceProtocol::Mcp,
            crate::config::ChannelProtocol::DIDComm => SurfaceProtocol::DIDComm,
        };

        let tags = match channel_type {
            crate::config::types::SurfaceType::Onboarding => vec!["system:onboarding".to_string()],
            crate::config::types::SurfaceType::System => vec!["system".to_string()],
            _ => vec![],
        };

        let target_policy = if opa_enabled {
            // opa_policy_definition_id is not stored in DynamoDB yet, so OPA
            // enforcement signals only — no policy ref to attach.
            None
        } else {
            None
        };

        let surface = AgentSurface {
            surface_id: config_id
                .clone()
                .unwrap_or_else(|| uuid::Uuid::new_v4().to_string()),
            name,
            description,
            status: SurfaceStatus::Active,
            tags,
            access_point: AccessPoint {
                listen_address,
                route,
                protocol: surface_protocol,
                caller_authentication: source_auth
                    .as_ref()
                    .map(|sa| CallerAuthentication {
                        methods: vec![sa.clone()],
                        protected_resource: None,
                        on_failure: crate::config::agent_surface::OnFailure::Continue,
                    }),
                public: Self::parse_public(&item),
                ..Default::default()
            },
            target: Target {
                endpoint: target_endpoint,
                auth: target_auth,
                custom_metadata,
                fabric_target_name,
                policy: target_policy,
                ..Default::default()
            },
            identity_slots: SurfaceIdentitySlots {
                protected: managed_identity,
                ..Default::default()
            },
            ..Default::default()
        };
        Ok(surface)
    }

    /// Helper to extract string attribute from DynamoDB item
    fn get_string_attribute(
        &self,
        item: &HashMap<String, aws_sdk_dynamodb::types::AttributeValue>,
        key: &str,
    ) -> Result<String> {
        item.get(key)
            .and_then(|v| v.as_s().ok())
            .map(|s| s.to_string())
            .with_context(|| format!("Missing or invalid string attribute: {}", key))
    }
}

#[async_trait]
impl ConfigurationStore for DynamoDbConfigStore {
    /// Load channels from DynamoDB
    /// Note: This only loads channels. TLS, A2A, and logging configurations
    /// should be provided from the bootstrap configuration.
    async fn load_config(&self) -> Result<GatewayConfig> {
        debug!("Loading channels from DynamoDB");

        let surfaces: Vec<crate::config::agent_surface::AgentSurface> = self.load_channels().await?;

        // Return a partial config with only channels
        // The caller will merge this with bootstrap config for TLS, A2A, and logging
        let config = GatewayConfig {
            surfaces,
            tls: TlsConfig {
                cert_path: std::path::PathBuf::from(""),
                key_path: std::path::PathBuf::from(""),
                verify_upstream: true,
                client_auth: Default::default(),
            },
            a2a: A2aConfig::default(),
            mcp: McpConfig::default(),
            logging: LoggingConfig::default(),
            extension_inspection: ExtensionInspectionConfig::default(),
            integration: IntegrationConfig::default_config(),
            facilitator_mode: crate::config::types::FacilitatorMode::default(),
            x402_headers: crate::config::types::X402Headers::default(),
        };

        info!("Channels loaded successfully from DynamoDB");
        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    use super::DynamoDbConfigStore;
    use aws_sdk_dynamodb::types::AttributeValue;
    use std::collections::HashMap;

    #[derive(Clone, Default)]
    struct CapturedLog(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

    impl std::io::Write for CapturedLog {
        fn write(
            &mut self,
            buf: &[u8],
        ) -> std::io::Result<usize> {
            self.0
                .lock()
                .unwrap()
                .extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn a_warning_raised_before_logging_starts_is_logged_once_when_it_starts() {
        let log = CapturedLog::default();
        let writer = log.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(move || writer.clone())
            .with_ansi(false)
            .finish();

        tracing::subscriber::with_default(subscriber, || {
            super::warn_when_logging("held-until-logging-starts-marker".to_string());
            let before = String::from_utf8(log.0.lock().unwrap().clone()).unwrap();
            assert!(!before.contains("held-until-logging-starts-marker"), "nothing is logged before the start");

            super::start_logging_warnings();
            super::start_logging_warnings();
        });

        let logged = String::from_utf8(log.0.lock().unwrap().clone()).unwrap();
        assert_eq!(
            logged
                .matches("held-until-logging-starts-marker")
                .count(),
            1,
            "{logged}"
        );
        assert!(logged.contains("WARN"), "{logged}");
    }

    #[test]
    fn parse_channel_protocol_defaults_to_a2a_when_missing() {
        let item = HashMap::new();
        let protocol = DynamoDbConfigStore::parse_channel_protocol(&item).expect("protocol should parse");
        assert_eq!(protocol, crate::config::ChannelProtocol::A2a);
    }

    #[test]
    fn warnings_recorded_before_logging_starts_are_held_and_flushed_in_order() {
        let mut deferred = super::DeferredWarnings::default();

        assert_eq!(deferred.record("first".to_string()), None);
        assert_eq!(deferred.record("second".to_string()), None);
        assert_eq!(deferred.start(), ["first".to_string(), "second".to_string()]);
        assert_eq!(deferred.start(), Vec::<String>::new(), "a flush leaves nothing pending");
    }

    #[test]
    fn warnings_recorded_once_logging_has_started_are_returned_to_log_at_once() {
        let mut deferred = super::DeferredWarnings::default();
        deferred.start();

        assert_eq!(deferred.record("late".to_string()), Some("late".to_string()));
        assert_eq!(deferred.start(), Vec::<String>::new(), "nothing is held back after the start");
    }

    #[test]
    fn the_ignored_public_message_names_the_item_and_only_the_type_of_the_value() {
        let message = |value: AttributeValue| super::ignored_public_message("orders", &value);

        assert_eq!(
            message(AttributeValue::S("yes".to_string())),
            "Ignoring the DynamoDB channel attribute 'public' of item 'orders': found string, expected a \
             boolean, or the string 'true' or 'false'; the surface keeps no Public access setting"
        );
        assert!(message(AttributeValue::N("1".to_string())).contains("found number,"));
        assert!(message(AttributeValue::Null(true)).contains("found null,"));
        assert!(message(AttributeValue::L(Vec::new())).contains("found list,"));
    }

    #[test]
    fn the_ignored_public_message_never_contains_the_value() {
        let map = AttributeValue::M(HashMap::from([("secret".to_string(), AttributeValue::S("hidden".to_string()))]));
        for value in [map, AttributeValue::S("hunter2".to_string()), AttributeValue::N("424242".to_string())] {
            let message = super::ignored_public_message("orders", &value);
            for leaked in ["hidden", "secret", "hunter2", "424242"] {
                assert!(!message.contains(leaked), "{message}");
            }
        }
    }

    #[test]
    fn parse_public_reads_the_optional_boolean_attribute() {
        assert_eq!(DynamoDbConfigStore::parse_public(&HashMap::new()), None, "missing: a legacy surface");
        for public in [true, false] {
            let item = HashMap::from([("public".to_string(), AttributeValue::Bool(public))]);
            assert_eq!(DynamoDbConfigStore::parse_public(&item), Some(public));
        }
        for (text, public) in [("true", Some(true)), ("false", Some(false)), ("yes", None)] {
            let item = HashMap::from([("public".to_string(), AttributeValue::S(text.to_string()))]);
            assert_eq!(DynamoDbConfigStore::parse_public(&item), public, "string {text:?}");
        }
        let number = HashMap::from([("public".to_string(), AttributeValue::N("1".to_string()))]);
        assert_eq!(DynamoDbConfigStore::parse_public(&number), None, "a number is not a boolean");
    }

    #[test]
    fn parse_channel_protocol_returns_err_for_invalid_explicit_value() {
        let mut item = HashMap::new();
        item.insert("protocol".to_string(), AttributeValue::S("marketplace".to_string()));

        let protocol = DynamoDbConfigStore::parse_channel_protocol(&item);
        assert!(protocol.is_err());
    }
}
