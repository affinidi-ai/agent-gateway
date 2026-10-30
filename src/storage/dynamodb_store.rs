use anyhow::{Context, Result, anyhow};
use async_trait::async_trait;
use aws_sdk_dynamodb::Client as DynamoDbClient;
use std::collections::HashMap;
use tracing::{debug, info, warn};

use crate::config::{
    A2aConfig, ExtensionInspectionConfig, GatewayConfig, IntegrationConfig, LoggingConfig, McpConfig, TlsConfig,
};
use crate::storage::ConfigurationStore;

/// DynamoDB-based configuration store
///
/// Expected DynamoDB table schema:
/// - Partition Key: `config_type` (String) - e.g., "channel", "tls", "a2a", "logging"
/// - Sort Key: `config_id` (String) - e.g., channel name, or "default" for singleton configs
///
/// Attributes depend on config_type:
/// - For channels: name, description, listen_address, target_endpoint, managed_identity (with extension_rules for identity schema)
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

        let channels = Self::readable_channels(
            result
                .items
                .unwrap_or_default(),
            |item| self.parse_channel_item(item),
        );

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

    /// The channels that parse and are not marked deleted; an item that does not parse is skipped.
    fn readable_channels(
        items: Vec<HashMap<String, aws_sdk_dynamodb::types::AttributeValue>>,
        mut parse: impl FnMut(
            HashMap<String, aws_sdk_dynamodb::types::AttributeValue>,
        ) -> Result<crate::config::agent_surface::AgentSurface>,
    ) -> Vec<crate::config::agent_surface::AgentSurface> {
        items
            .into_iter()
            .filter_map(|item| Self::skip_unreadable(parse(item)))
            .filter(|surface| surface.status != crate::config::agent_surface::SurfaceStatus::Deleted)
            .collect()
    }

    /// An item that cannot be read is logged and counted, and the other channels still load.
    fn skip_unreadable(
        parsed: Result<crate::config::agent_surface::AgentSurface>
    ) -> Option<crate::config::agent_surface::AgentSurface> {
        match parsed {
            Ok(surface) => Some(surface),
            Err(error) => {
                warn!("Skipping an unreadable DynamoDB channel: {error:#}");
                crate::metrics::backends::prometheus::track_storage_load_error("dynamodb_channel", "unreadable_record");
                None
            }
        }
    }

    /// An unreadable `target_auth` fails the item instead of reading as none: a method
    /// from a newer release must not leave the surface forwarding without its credential.
    fn parse_target_auth(
        item: &HashMap<String, aws_sdk_dynamodb::types::AttributeValue>,
        config_id: &str,
    ) -> Result<Option<crate::config::types::TargetAuthConfig>> {
        let Some(raw) = item
            .get("target_auth")
            .and_then(|value| value.as_s().ok())
        else {
            return Ok(None);
        };
        serde_json::from_str(raw)
            .map(Some)
            .map_err(|_| anyhow!("Unreadable target_auth on channel '{config_id}'; it may come from a newer release"))
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

        let target_auth = Self::parse_target_auth(
            &item,
            config_id
                .as_deref()
                .unwrap_or_default(),
        )?;

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
                    }),
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

    #[test]
    fn parse_channel_protocol_defaults_to_a2a_when_missing() {
        let item = HashMap::new();
        let protocol = DynamoDbConfigStore::parse_channel_protocol(&item).expect("protocol should parse");
        assert_eq!(protocol, crate::config::ChannelProtocol::A2a);
    }

    #[test]
    fn parse_channel_protocol_returns_err_for_invalid_explicit_value() {
        let mut item = HashMap::new();
        item.insert("protocol".to_string(), AttributeValue::S("marketplace".to_string()));

        let protocol = DynamoDbConfigStore::parse_channel_protocol(&item);
        assert!(protocol.is_err());
    }
}

#[cfg(test)]
mod target_auth_tests {
    use super::*;
    use aws_sdk_dynamodb::types::AttributeValue;

    fn unreadable_channels() -> u64 {
        crate::metrics::backends::prometheus::STORAGE_LOAD_ERRORS
            .with_label_values(&["dynamodb_channel", "unreadable_record"])
            .get()
    }

    #[test]
    fn an_unreadable_channel_is_skipped_and_counted_while_a_readable_one_is_kept() {
        let before = unreadable_channels();
        let kept = DynamoDbConfigStore::skip_unreadable(Ok(crate::config::agent_surface::AgentSurface::default()));
        assert!(kept.is_some());

        let dropped = DynamoDbConfigStore::skip_unreadable(Err(anyhow!("unreadable")));
        assert!(dropped.is_none());
        assert!(unreadable_channels() > before, "the counter is shared with parallel tests, so it only rises");
    }

    #[test]
    fn one_unreadable_item_among_readable_ones_is_skipped_and_counted_while_the_rest_load() {
        use crate::config::agent_surface::{AgentSurface, SurfaceStatus};
        let named = |name: &str| {
            let mut item = HashMap::new();
            item.insert("name".to_string(), AttributeValue::S(name.to_string()));
            item
        };
        let before = unreadable_channels();
        let channels = DynamoDbConfigStore::readable_channels(
            vec![named("first"), named("broken"), named("gone"), named("last")],
            |item| {
                let name = item["name"]
                    .as_s()
                    .unwrap()
                    .clone();
                match name.as_str() {
                    "broken" => Err(anyhow!("unreadable")),
                    "gone" => Ok(AgentSurface {
                        name,
                        status: SurfaceStatus::Deleted,
                        ..AgentSurface::default()
                    }),
                    _ => Ok(AgentSurface {
                        name,
                        ..AgentSurface::default()
                    }),
                }
            },
        );
        let names: Vec<_> = channels
            .iter()
            .map(|surface| surface.name.as_str())
            .collect();
        assert_eq!(names, vec!["first", "last"]);
        assert!(unreadable_channels() > before, "the counter is shared with parallel tests, so it only rises");
    }

    fn item_with(target_auth: Option<&str>) -> HashMap<String, AttributeValue> {
        let mut item = HashMap::new();
        if let Some(target_auth) = target_auth {
            item.insert("target_auth".to_string(), AttributeValue::S(target_auth.to_string()));
        }
        item
    }

    fn parsed(target_auth: Option<&str>) -> Result<Option<crate::config::types::TargetAuthConfig>> {
        DynamoDbConfigStore::parse_target_auth(&item_with(target_auth), "channel-1")
    }

    #[test]
    fn a_missing_target_auth_is_none() {
        assert_eq!(parsed(None).unwrap(), None);
    }

    #[test]
    fn a_readable_target_auth_is_returned() {
        let auth = parsed(Some(r#"{"method":{"static_secret":{"secret_id":"S","header_name":"X"}}}"#))
            .unwrap()
            .expect("target auth is read");
        assert!(matches!(auth.method, crate::config::types::TargetAuthMethod::StaticSecret { .. }));
    }

    #[test]
    fn a_target_auth_method_from_a_newer_release_fails_the_item() {
        let error = parsed(Some(r#"{"method":{"a_method_from_a_newer_release":{}}}"#)).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("channel-1"),
            "{error}"
        );
        assert!(
            !error
                .to_string()
                .contains("a_method_from_a_newer_release"),
            "the stored text is not echoed"
        );
    }
}
