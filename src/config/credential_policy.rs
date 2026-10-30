//! Bootstrap `[credential_policy]` section: how strictly credential providers
//! are held to the token endpoint and tenant isolation rules.
//!
//! Read once at startup and held in a process-global; changing it needs a restart.

use std::sync::OnceLock;

use serde::{Deserialize, Serialize};

/// How a credential rule is applied.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum RuleMode {
    /// Stored configurations that break the rule keep working with a warning;
    /// new or changed ones are refused on save.
    #[default]
    Warn,
    /// A configuration that breaks the rule is refused at runtime as well.
    Enforce,
}

impl RuleMode {
    #[allow(dead_code)]
    pub fn is_enforced(self) -> bool {
        self == Self::Enforce
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct CredentialPolicyConfig {
    /// Whether a credential provider's token endpoint must use https.
    pub token_endpoint_https: RuleMode,
    /// Whether a credential provider may only use secrets of its own tenant.
    pub tenant_credential_isolation: RuleMode,
    /// Exact token endpoint URLs that may use http deliberately.
    pub insecure_token_endpoints: Vec<String>,
}

impl CredentialPolicyConfig {
    #[allow(dead_code)]
    pub fn allows_insecure_token_endpoint(
        &self,
        url: &str,
    ) -> bool {
        self.insecure_token_endpoints
            .iter()
            .any(|allowed| allowed == url)
    }
}

static GLOBAL_CREDENTIAL_POLICY: OnceLock<CredentialPolicyConfig> = OnceLock::new();

/// Install the process-global credential policy. First writer wins; later calls are ignored.
pub fn init_credential_policy(config: CredentialPolicyConfig) {
    let _ = GLOBAL_CREDENTIAL_POLICY.set(config);
}

/// The process-global credential policy; the warn defaults before initialisation.
#[allow(dead_code)]
pub fn credential_policy() -> &'static CredentialPolicyConfig {
    GLOBAL_CREDENTIAL_POLICY.get_or_init(CredentialPolicyConfig::default)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_warn_with_no_allowlist() {
        let config = CredentialPolicyConfig::default();
        assert_eq!(config.token_endpoint_https, RuleMode::Warn);
        assert_eq!(config.tenant_credential_isolation, RuleMode::Warn);
        assert!(
            config
                .insecure_token_endpoints
                .is_empty()
        );
        assert!(!RuleMode::Warn.is_enforced());
        assert!(RuleMode::Enforce.is_enforced());
    }

    #[test]
    fn parses_every_value() {
        let config: CredentialPolicyConfig = toml::from_str(
            "token_endpoint_https = \"enforce\"\ntenant_credential_isolation = \"warn\"\ninsecure_token_endpoints = [\"http://idp.internal/token\"]\n",
        )
        .unwrap();
        assert_eq!(config.token_endpoint_https, RuleMode::Enforce);
        assert_eq!(config.tenant_credential_isolation, RuleMode::Warn);
        assert!(config.allows_insecure_token_endpoint("http://idp.internal/token"));
        assert!(!config.allows_insecure_token_endpoint("http://idp.internal/token2"));
        assert!(!config.allows_insecure_token_endpoint("http://idp.internal"));

        let config: CredentialPolicyConfig = toml::from_str("tenant_credential_isolation = \"enforce\"").unwrap();
        assert_eq!(config.token_endpoint_https, RuleMode::Warn);
        assert_eq!(config.tenant_credential_isolation, RuleMode::Enforce);
    }

    #[test]
    fn unknown_mode_is_refused() {
        assert!(toml::from_str::<CredentialPolicyConfig>("token_endpoint_https = \"off\"").is_err());
        assert!(toml::from_str::<CredentialPolicyConfig>("tenant_credential_isolation = \"Enforce\"").is_err());
        assert!(toml::from_str::<CredentialPolicyConfig>("token_endpoint_https = true").is_err());
    }

    #[test]
    fn absent_section_in_bootstrap_is_warn() {
        let config: crate::config::BootstrapConfig =
            toml::from_str("backup_encryption_key = \"00\"\n[tls]\ncert_path = \"cert.pem\"\nkey_path = \"key.pem\"\n")
                .unwrap();
        assert_eq!(config.credential_policy, CredentialPolicyConfig::default());

        let config: crate::config::BootstrapConfig = toml::from_str(
            "backup_encryption_key = \"00\"\n[credential_policy]\ntoken_endpoint_https = \"enforce\"\n[tls]\ncert_path = \"cert.pem\"\nkey_path = \"key.pem\"\n",
        )
        .unwrap();
        assert_eq!(
            config
                .credential_policy
                .token_endpoint_https,
            RuleMode::Enforce
        );
        assert_eq!(
            config
                .credential_policy
                .tenant_credential_isolation,
            RuleMode::Warn
        );
    }
}
