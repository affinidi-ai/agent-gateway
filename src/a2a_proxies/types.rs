use crate::storage::filesystem::StorableEntity;
use serde::{Deserialize, Serialize};

pub const DEFAULT_DIRECT_LINE_TIMEOUT_SECS: u32 = 30;
pub const MIN_DIRECT_LINE_TIMEOUT_SECS: u32 = 1;
pub const MAX_DIRECT_LINE_TIMEOUT_SECS: u32 = 120;
pub const DEFAULT_DIRECT_LINE_POLL_INTERVAL_MS: u32 = 500;
pub const MIN_DIRECT_LINE_POLL_INTERVAL_MS: u32 = 100;
pub const MAX_DIRECT_LINE_POLL_INTERVAL_MS: u32 = 5_000;
pub const DEFAULT_DIRECT_LINE_MAX_POLL_ATTEMPTS: u32 = 60;
pub const DEFAULT_DIRECT_LINE_BASE_URL: &str = "https://directline.botframework.com/v3/directline";
pub const MIN_DIRECT_LINE_MAX_POLL_ATTEMPTS: u32 = 1;
pub const MAX_DIRECT_LINE_MAX_POLL_ATTEMPTS: u32 = 240;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "lowercase")]
pub enum A2aProxyStatus {
    #[default]
    Active,
    Disabled,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct A2aProxy {
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub status: A2aProxyStatus,
    pub backend: A2aProxyBackend,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_card: Option<A2aProxyAgentCardProfile>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_identity: Option<A2aProxyAgentIdentity>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum A2aProxyBackend {
    CopilotDirectLine(CopilotDirectLineBackend),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CopilotDirectLineBackend {
    pub secret_id: String,
    #[serde(default)]
    pub credential_mode: DirectLineCredentialMode,
    #[serde(default = "default_direct_line_base_url")]
    pub base_url: String,
    #[serde(default = "default_direct_line_timeout_secs")]
    pub timeout_secs: u32,
    #[serde(default = "default_direct_line_poll_interval_ms")]
    pub poll_interval_ms: u32,
    #[serde(default = "default_direct_line_max_poll_attempts")]
    pub max_poll_attempts: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "snake_case")]
pub enum DirectLineCredentialMode {
    #[default]
    Secret,
    GenerateToken,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct A2aProxyAgentCardProfile {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "snake_case")]
pub enum A2aProxyAgentIdentityType {
    #[default]
    ProxySubject,
    EntraAgent,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct A2aProxyAgentIdentity {
    #[serde(rename = "type", default, skip_serializing_if = "is_default_agent_identity_type")]
    pub identity_type: A2aProxyAgentIdentityType,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entra_agent_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_tenant_id: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct CreateA2aProxyRequest {
    #[serde(default)]
    pub tenant_id: Option<String>,
    pub name: String,
    #[serde(default)]
    pub description: String,
    pub backend: A2aProxyBackend,
    #[serde(default)]
    pub agent_card: Option<A2aProxyAgentCardProfile>,
    #[serde(default)]
    pub agent_identity: Option<A2aProxyAgentIdentity>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateA2aProxyRequest {
    pub name: Option<String>,
    pub description: Option<String>,
    pub status: Option<A2aProxyStatus>,
    pub backend: Option<A2aProxyBackend>,
    pub agent_card: Option<Option<A2aProxyAgentCardProfile>>,
    pub agent_identity: Option<Option<A2aProxyAgentIdentity>>,
}

impl A2aProxy {
    pub fn new(
        name: String,
        description: String,
        backend: A2aProxyBackend,
        agent_card: Option<A2aProxyAgentCardProfile>,
    ) -> Self {
        let now = chrono::Utc::now();
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            tenant_id: None,
            name,
            description,
            status: A2aProxyStatus::Active,
            backend,
            agent_card,
            agent_identity: None,
            created_at: now,
            updated_at: now,
        }
    }

    pub fn validate(&self) -> Result<(), String> {
        validate_non_empty("name", &self.name)?;
        if let Some(agent_card) = &self.agent_card {
            if let Some(name) = &agent_card.name {
                validate_non_empty("agent_card.name", name)?;
            }
            if let Some(description) = &agent_card.description {
                validate_non_empty("agent_card.description", description)?;
            }
        }
        if let Some(agent_identity) = &self.agent_identity {
            agent_identity.validate()?;
        }
        self.backend.validate()
    }
}

impl A2aProxyBackend {
    pub fn validate(&self) -> Result<(), String> {
        match self {
            Self::CopilotDirectLine(backend) => backend.validate(),
        }
    }

    pub fn kind_label(&self) -> &'static str {
        match self {
            Self::CopilotDirectLine(_) => "copilot_direct_line",
        }
    }
}

impl A2aProxyAgentIdentity {
    pub fn subject_or_proxy_id<'a>(
        &'a self,
        proxy_id: &'a str,
    ) -> &'a str {
        self.subject
            .as_deref()
            .unwrap_or(proxy_id)
    }

    pub fn validate(&self) -> Result<(), String> {
        match self.identity_type {
            A2aProxyAgentIdentityType::ProxySubject => {
                if let Some(subject) = &self.subject {
                    validate_identity_text_field("agent_identity.subject", subject)?;
                }
            }
            A2aProxyAgentIdentityType::EntraAgent => {
                validate_required_identity_text_field("agent_identity.entra_agent_id", self.entra_agent_id.as_deref())?;
                validate_required_identity_text_field(
                    "agent_identity.client_tenant_id",
                    self.client_tenant_id
                        .as_deref(),
                )?;
            }
        }
        Ok(())
    }
}

impl CopilotDirectLineBackend {
    pub fn validate(&self) -> Result<(), String> {
        validate_non_empty("backend.secret_id", &self.secret_id)?;
        validate_non_empty("backend.base_url", &self.base_url)?;
        // The dial carries the tenant Direct Line credential, so an attacker who
        // can set `base_url` (an operator, or an unauthenticated caller on a
        // no-auth deploy) must never point it at loopback / RFC 1918 / link-local
        // / cloud-metadata. Validate strictly at config-set time; the dial re-vets
        // with the same policy (defense in depth against values predating this).
        crate::url_validation::validate_webhook_url(&self.base_url)
            .map_err(|e| format!("backend.base_url is not a permitted egress target: {e}"))?;
        validate_range(
            "backend.timeout_secs",
            self.timeout_secs,
            MIN_DIRECT_LINE_TIMEOUT_SECS,
            MAX_DIRECT_LINE_TIMEOUT_SECS,
        )?;
        validate_range(
            "backend.poll_interval_ms",
            self.poll_interval_ms,
            MIN_DIRECT_LINE_POLL_INTERVAL_MS,
            MAX_DIRECT_LINE_POLL_INTERVAL_MS,
        )?;
        validate_range(
            "backend.max_poll_attempts",
            self.max_poll_attempts,
            MIN_DIRECT_LINE_MAX_POLL_ATTEMPTS,
            MAX_DIRECT_LINE_MAX_POLL_ATTEMPTS,
        )
    }
}

impl StorableEntity for A2aProxy {
    fn id(&self) -> &str {
        &self.id
    }
}

fn default_direct_line_base_url() -> String {
    DEFAULT_DIRECT_LINE_BASE_URL.to_string()
}

fn default_direct_line_timeout_secs() -> u32 {
    DEFAULT_DIRECT_LINE_TIMEOUT_SECS
}

fn default_direct_line_poll_interval_ms() -> u32 {
    DEFAULT_DIRECT_LINE_POLL_INTERVAL_MS
}

fn default_direct_line_max_poll_attempts() -> u32 {
    DEFAULT_DIRECT_LINE_MAX_POLL_ATTEMPTS
}

fn validate_non_empty(
    field: &str,
    value: &str,
) -> Result<(), String> {
    if value.trim().is_empty() {
        Err(format!("{field} must not be empty"))
    } else {
        Ok(())
    }
}

fn is_default_agent_identity_type(identity_type: &A2aProxyAgentIdentityType) -> bool {
    matches!(identity_type, A2aProxyAgentIdentityType::ProxySubject)
}

fn validate_required_identity_text_field(
    field: &str,
    value: Option<&str>,
) -> Result<(), String> {
    let value = value.ok_or_else(|| format!("{field} must not be empty"))?;
    validate_identity_text_field(field, value)
}

fn validate_identity_text_field(
    field: &str,
    value: &str,
) -> Result<(), String> {
    validate_non_empty(field, value)?;
    if value.chars().count() > 128 {
        return Err(format!("{field} must be at most 128 characters"));
    }
    if contains_unsafe_control(value) {
        return Err(format!("{field} must not contain control or bidi override characters"));
    }
    Ok(())
}

fn contains_unsafe_control(value: &str) -> bool {
    value.chars().any(
        |ch| matches!(ch, '\u{0000}'..='\u{001f}' | '\u{007f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}'),
    )
}

fn validate_range(
    field: &str,
    value: u32,
    min: u32,
    max: u32,
) -> Result<(), String> {
    if (min..=max).contains(&value) {
        Ok(())
    } else {
        Err(format!("{field} must be between {min} and {max}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn backend() -> A2aProxyBackend {
        A2aProxyBackend::CopilotDirectLine(CopilotDirectLineBackend {
            secret_id: "direct-line-secret".to_string(),
            credential_mode: DirectLineCredentialMode::Secret,
            base_url: DEFAULT_DIRECT_LINE_BASE_URL.to_string(),
            timeout_secs: DEFAULT_DIRECT_LINE_TIMEOUT_SECS,
            poll_interval_ms: DEFAULT_DIRECT_LINE_POLL_INTERVAL_MS,
            max_poll_attempts: DEFAULT_DIRECT_LINE_MAX_POLL_ATTEMPTS,
        })
    }

    #[test]
    fn new_proxy_defaults_to_active() {
        let proxy = A2aProxy::new("worker".to_string(), String::new(), backend(), None);

        assert_eq!(proxy.status, A2aProxyStatus::Active);
        assert!(proxy.validate().is_ok());
    }

    #[test]
    fn direct_line_credential_mode_uses_generate_token_wire_value() {
        let mode = DirectLineCredentialMode::GenerateToken;
        let serialized = serde_json::to_value(mode).expect("serialize credential mode");
        assert_eq!(serialized, serde_json::json!("generate_token"));
    }

    #[test]
    fn validation_rejects_blank_secret_id() {
        let proxy = A2aProxy::new(
            "worker".to_string(),
            String::new(),
            A2aProxyBackend::CopilotDirectLine(CopilotDirectLineBackend {
                secret_id: " ".to_string(),
                credential_mode: DirectLineCredentialMode::Secret,
                base_url: DEFAULT_DIRECT_LINE_BASE_URL.to_string(),
                timeout_secs: DEFAULT_DIRECT_LINE_TIMEOUT_SECS,
                poll_interval_ms: DEFAULT_DIRECT_LINE_POLL_INTERVAL_MS,
                max_poll_attempts: DEFAULT_DIRECT_LINE_MAX_POLL_ATTEMPTS,
            }),
            None,
        );

        assert_eq!(proxy.validate().unwrap_err(), "backend.secret_id must not be empty");
    }

    #[test]
    fn validation_rejects_out_of_range_poll_settings() {
        let proxy = A2aProxy::new(
            "worker".to_string(),
            String::new(),
            A2aProxyBackend::CopilotDirectLine(CopilotDirectLineBackend {
                secret_id: "direct-line-secret".to_string(),
                credential_mode: DirectLineCredentialMode::Secret,
                base_url: DEFAULT_DIRECT_LINE_BASE_URL.to_string(),
                timeout_secs: 0,
                poll_interval_ms: DEFAULT_DIRECT_LINE_POLL_INTERVAL_MS,
                max_poll_attempts: DEFAULT_DIRECT_LINE_MAX_POLL_ATTEMPTS,
            }),
            None,
        );

        assert_eq!(proxy.validate().unwrap_err(), "backend.timeout_secs must be between 1 and 120");
    }

    fn backend_with_base_url(base_url: &str) -> A2aProxyBackend {
        A2aProxyBackend::CopilotDirectLine(CopilotDirectLineBackend {
            secret_id: "direct-line-secret".to_string(),
            credential_mode: DirectLineCredentialMode::Secret,
            base_url: base_url.to_string(),
            timeout_secs: DEFAULT_DIRECT_LINE_TIMEOUT_SECS,
            poll_interval_ms: DEFAULT_DIRECT_LINE_POLL_INTERVAL_MS,
            max_poll_attempts: DEFAULT_DIRECT_LINE_MAX_POLL_ATTEMPTS,
        })
    }

    #[test]
    fn validation_rejects_ssrf_base_url() {
        // `base_url` carries the tenant credential, so config-set time must reject a
        // loopback / private / metadata target (parity with the strict dial guard).
        for base_url in [
            "http://127.0.0.1/directline",
            "http://10.0.0.5/directline",
            "http://192.168.1.10/directline",
            "http://169.254.169.254/latest/meta-data/",
        ] {
            let proxy = A2aProxy::new("worker".to_string(), String::new(), backend_with_base_url(base_url), None);
            assert!(
                proxy
                    .validate()
                    .unwrap_err()
                    .starts_with("backend.base_url is not a permitted egress target"),
                "base_url {base_url} must be rejected"
            );
        }
    }

    #[test]
    fn validation_allows_public_base_url() {
        let proxy = A2aProxy::new(
            "worker".to_string(),
            String::new(),
            backend_with_base_url("https://directline.botframework.com/v3/directline"),
            None,
        );
        assert!(proxy.validate().is_ok());
    }

    #[test]
    fn legacy_agent_identity_subject_deserializes_as_proxy_subject() {
        let identity: A2aProxyAgentIdentity = serde_json::from_value(serde_json::json!({
            "subject": "support-copilot-prod"
        }))
        .expect("legacy identity");

        assert_eq!(identity.identity_type, A2aProxyAgentIdentityType::ProxySubject);
        assert_eq!(identity.subject.as_deref(), Some("support-copilot-prod"));
        assert!(identity.validate().is_ok());
    }

    #[test]
    fn entra_agent_identity_round_trips_and_validates() {
        let identity: A2aProxyAgentIdentity = serde_json::from_value(serde_json::json!({
            "type": "entra_agent",
            "entra_agent_id": "00000000-0000-0000-0000-000000000000",
            "client_tenant_id": "11111111-1111-1111-1111-111111111111"
        }))
        .expect("entra identity");

        assert_eq!(identity.identity_type, A2aProxyAgentIdentityType::EntraAgent);
        assert!(identity.validate().is_ok());
        let serialized = serde_json::to_value(&identity).expect("serialize identity");
        assert_eq!(serialized["type"], "entra_agent");
        assert_eq!(serialized["entra_agent_id"], "00000000-0000-0000-0000-000000000000");
        assert_eq!(serialized["client_tenant_id"], "11111111-1111-1111-1111-111111111111");
    }

    #[test]
    fn entra_agent_identity_rejects_missing_fields() {
        let identity: A2aProxyAgentIdentity = serde_json::from_value(serde_json::json!({
            "type": "entra_agent",
            "entra_agent_id": "agent-123"
        }))
        .expect("entra identity");

        assert_eq!(
            identity
                .validate()
                .unwrap_err(),
            "agent_identity.client_tenant_id must not be empty"
        );
    }

    #[test]
    fn agent_identity_rejects_unsafe_text() {
        let identity: A2aProxyAgentIdentity = serde_json::from_value(serde_json::json!({
            "type": "entra_agent",
            "entra_agent_id": "agent-123",
            "client_tenant_id": "tenant\u{202e}"
        }))
        .expect("entra identity");

        assert_eq!(
            identity
                .validate()
                .unwrap_err(),
            "agent_identity.client_tenant_id must not contain control or bidi override characters"
        );
    }
}
