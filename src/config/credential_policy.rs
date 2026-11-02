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
    pub fn is_enforced(self) -> bool {
        self == Self::Enforce
    }
}

pub const DEFAULT_TOKEN_REQUEST_TIMEOUT_SECS: u64 = 30;
pub const MAX_TOKEN_REQUEST_TIMEOUT_SECS: u64 = 120;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct CredentialPolicyConfig {
    /// Whether a credential provider's token endpoint must use https.
    pub token_endpoint_https: RuleMode,
    /// Whether a credential provider may only use secrets of its own tenant.
    pub tenant_credential_isolation: RuleMode,
    /// Exact token endpoint URLs that may use http deliberately.
    pub insecure_token_endpoints: Vec<String>,
    /// Seconds a credential provider token request may take, 1 to 120.
    pub token_request_timeout_secs: u64,
}

impl Default for CredentialPolicyConfig {
    fn default() -> Self {
        Self {
            token_endpoint_https: RuleMode::default(),
            tenant_credential_isolation: RuleMode::default(),
            insecure_token_endpoints: Vec::new(),
            token_request_timeout_secs: DEFAULT_TOKEN_REQUEST_TIMEOUT_SECS,
        }
    }
}

impl CredentialPolicyConfig {
    /// Refuses a `token_request_timeout_secs` of 0 or above 120, and an
    /// `insecure_token_endpoints` entry that is not an absolute http URL without userinfo.
    pub fn validate(&self) -> Result<(), String> {
        if !(1..=MAX_TOKEN_REQUEST_TIMEOUT_SECS).contains(&self.token_request_timeout_secs) {
            return Err(format!(
                "token_request_timeout_secs must be from 1 to {MAX_TOKEN_REQUEST_TIMEOUT_SECS}, got {}",
                self.token_request_timeout_secs
            ));
        }
        for entry in &self.insecure_token_endpoints {
            let Ok(mut url) = url::Url::parse(entry.trim()) else {
                return Err(format!("insecure_token_endpoints entry \"{entry}\" is not a valid URL"));
            };
            if url.scheme() != "http" {
                return Err(format!("insecure_token_endpoints entry \"{entry}\" must be an http URL"));
            }
            if !url.username().is_empty() || url.password().is_some() {
                let _ = url.set_username("");
                let _ = url.set_password(None);
                return Err(format!("insecure_token_endpoints entry \"{url}\" must not carry credentials"));
            }
        }
        Ok(())
    }

    /// Whether `insecure_token_endpoints` names `url` exactly, compared as parsed URLs.
    pub fn allows_insecure_token_endpoint(
        &self,
        url: &str,
    ) -> bool {
        let Ok(url) = url::Url::parse(url.trim()) else {
            return false;
        };
        self.insecure_token_endpoints
            .iter()
            .filter_map(|allowed| url::Url::parse(allowed.trim()).ok())
            .any(|allowed| allowed == url)
    }
}

static GLOBAL_CREDENTIAL_POLICY: OnceLock<CredentialPolicyConfig> = OnceLock::new();

/// Install the process-global credential policy. First writer wins; later calls are ignored.
pub fn init_credential_policy(config: CredentialPolicyConfig) {
    let _ = GLOBAL_CREDENTIAL_POLICY.set(config);
}

#[cfg(test)]
tokio::task_local! {
    /// The credential policy [`credential_policy`] returns inside a test's scope, instead of the
    /// process-global one, which is set once per process.
    pub(crate) static TEST_CREDENTIAL_POLICY: &'static CredentialPolicyConfig;
}

#[cfg(test)]
thread_local! {
    static TEST_THREAD_CREDENTIAL_POLICY: std::cell::Cell<Option<&'static CredentialPolicyConfig>> =
        const { std::cell::Cell::new(None) };
}

/// Makes the current thread read `policy` from [`credential_policy`], so every task a runtime
/// runs on a thread prepared this way, such as an in-process gateway's, sees it.
#[cfg(test)]
pub(crate) fn use_thread_credential_policy(policy: CredentialPolicyConfig) {
    let policy: &'static CredentialPolicyConfig = Box::leak(Box::new(policy));
    TEST_THREAD_CREDENTIAL_POLICY.with(|slot| slot.set(Some(policy)));
}

/// The process-global credential policy; the warn defaults before initialisation.
pub fn credential_policy() -> &'static CredentialPolicyConfig {
    #[cfg(test)]
    if let Ok(policy) = TEST_CREDENTIAL_POLICY.try_with(|policy| *policy) {
        return policy;
    }
    #[cfg(test)]
    if let Some(policy) = TEST_THREAD_CREDENTIAL_POLICY.with(std::cell::Cell::get) {
        return policy;
    }
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
        assert!(config.allows_insecure_token_endpoint(" HTTP://IDP.internal/token "));
        assert!(!config.allows_insecure_token_endpoint("http://idp.internal:8080/token"));
        assert!(!config.allows_insecure_token_endpoint("not a url"));

        let config: CredentialPolicyConfig = toml::from_str("tenant_credential_isolation = \"enforce\"").unwrap();
        assert_eq!(config.token_endpoint_https, RuleMode::Warn);
        assert_eq!(config.tenant_credential_isolation, RuleMode::Enforce);
    }

    #[test]
    fn token_request_timeout_defaults_to_thirty_and_takes_a_configured_value() {
        assert_eq!(CredentialPolicyConfig::default().token_request_timeout_secs, 30);
        let absent: CredentialPolicyConfig = toml::from_str("token_endpoint_https = \"enforce\"").unwrap();
        assert_eq!(absent.token_request_timeout_secs, 30);
        let set: CredentialPolicyConfig = toml::from_str("token_request_timeout_secs = 45").unwrap();
        assert_eq!(set.token_request_timeout_secs, 45);
        assert_eq!(set.validate(), Ok(()));
    }

    #[test]
    fn token_request_timeout_outside_one_to_one_twenty_is_refused() {
        for (secs, valid) in [(0, false), (1, true), (120, true), (121, false)] {
            let config: CredentialPolicyConfig =
                toml::from_str(&format!("token_request_timeout_secs = {secs}")).unwrap();
            assert_eq!(config.validate().is_ok(), valid, "{secs}");
        }
        assert_eq!(
            CredentialPolicyConfig {
                token_request_timeout_secs: 0,
                ..Default::default()
            }
            .validate(),
            Err("token_request_timeout_secs must be from 1 to 120, got 0".to_string())
        );
        assert!(toml::from_str::<CredentialPolicyConfig>("token_request_timeout_secs = -1").is_err());
    }

    #[test]
    fn an_insecure_token_endpoint_entry_must_be_an_http_url_without_credentials() {
        let with = |entry: &str| CredentialPolicyConfig {
            insecure_token_endpoints: vec![entry.to_string()],
            ..Default::default()
        };
        assert_eq!(with("http://idp.internal/token").validate(), Ok(()));
        assert_eq!(with(" http://idp.internal:8080/token ").validate(), Ok(()));
        assert_eq!(
            with("htp://idp.internal/token").validate(),
            Err("insecure_token_endpoints entry \"htp://idp.internal/token\" must be an http URL".to_string())
        );
        assert_eq!(
            with("idp.internal/token").validate(),
            Err("insecure_token_endpoints entry \"idp.internal/token\" is not a valid URL".to_string())
        );
        assert_eq!(
            with("https://idp.internal/token").validate(),
            Err("insecure_token_endpoints entry \"https://idp.internal/token\" must be an http URL".to_string())
        );
        assert_eq!(
            with("http://user:hunter2@idp.internal/token").validate(),
            Err("insecure_token_endpoints entry \"http://idp.internal/token\" must not carry credentials".to_string())
        );
        let mixed = CredentialPolicyConfig {
            insecure_token_endpoints: vec!["http://idp.internal/token".into(), "http//typo".into()],
            ..Default::default()
        };
        assert!(
            mixed
                .validate()
                .unwrap_err()
                .contains("http//typo")
        );
    }

    #[test]
    fn the_bootstrap_validation_refuses_a_malformed_insecure_token_endpoint() {
        let directory = tempfile::tempdir().unwrap();
        let cert = directory
            .path()
            .join("cert.pem");
        let key = directory
            .path()
            .join("key.pem");
        std::fs::write(&cert, "").unwrap();
        std::fs::write(&key, "").unwrap();
        let config = |entry: &str| -> crate::config::BootstrapConfig {
            toml::from_str(&format!(
                "backup_encryption_key = \"00\"\n[credential_policy]\ninsecure_token_endpoints = [\"{entry}\"]\n[tls]\ncert_path = {:?}\nkey_path = {:?}\n",
                cert.to_str().unwrap(),
                key.to_str().unwrap()
            ))
            .unwrap()
        };
        assert!(
            config("http://idp.internal/token")
                .validate()
                .is_ok()
        );
        let error = config("htp://idp.internal/token")
            .validate()
            .unwrap_err()
            .to_string();
        assert_eq!(
            error,
            "Invalid [credential_policy] config: insecure_token_endpoints entry \"htp://idp.internal/token\" must be an http URL"
        );
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
