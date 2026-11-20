use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

/// Authentication mode
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
#[derive(Default)]
pub enum AuthMode {
    /// WebAuthn passkey authentication
    #[default]
    Passkey,
    /// SAML 2.0 authentication
    Saml,
}

/// SAML authentication configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamlConfig {
    /// Azure AD entity ID (Identity Provider)
    pub idp_entity_id: String,

    /// Azure AD Single Sign-On URL
    pub idp_sso_url: String,

    /// Azure AD Sign-Out URL (optional)
    pub idp_slo_url: Option<String>,

    /// Service Provider entity ID (your application)
    pub sp_entity_id: String,

    /// Assertion Consumer Service URL (where Azure AD posts SAML response)
    pub sp_acs_url: String,

    /// Path to Azure AD certificate for signature verification
    pub idp_cert_path: String,

    /// Attribute mappings from SAML to user fields
    #[serde(default)]
    pub attribute_mapping: SamlAttributeMapping,

    /// Role mapping from Azure AD roles/groups to RBAC roles
    #[serde(default)]
    pub role_mapping: HashMap<String, String>,

    /// Role for a sign-in whose identity-provider role has no `role_mapping` entry.
    /// Unset: such a sign-in is refused.
    #[serde(default)]
    pub default_role: Option<String>,

    /// Require encrypted assertions (default: false)
    #[serde(default)]
    pub require_encrypted_assertions: bool,

    /// Sign authentication requests (default: true)
    #[serde(default = "default_true")]
    pub sign_requests: bool,

    /// Path to SP private key for signing (required if sign_requests = true)
    pub sp_key_path: Option<String>,

    /// Path to SP certificate (required if sign_requests = true)
    pub sp_cert_path: Option<String>,

    /// Microsoft Graph API configuration for fetching user avatars (optional)
    #[serde(default)]
    pub graph_api: Option<GraphApiConfig>,

    /// Per-client-IP limit on starting a SAML sign-in.
    #[serde(default)]
    pub login_throttle: crate::config::types::LoginThrottleConfig,
}

/// Microsoft Graph API configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphApiConfig {
    /// Azure AD tenant ID
    pub tenant_id: String,

    /// Azure AD application (client) ID
    pub client_id: String,

    /// Azure AD application client secret
    pub client_secret: String,

    /// Fetch user avatar on login (default: false)
    #[serde(default)]
    pub fetch_avatar: bool,
}

/// SAML attribute mapping configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamlAttributeMapping {
    /// Attribute containing user ID
    #[serde(default = "default_saml_user_id_attribute")]
    pub user_id: String,

    /// Attribute containing username
    #[serde(default = "default_saml_username_attribute")]
    pub username: String,

    /// Attribute containing email
    #[serde(default = "default_saml_email_attribute")]
    pub email: String,

    /// Attribute containing first name
    #[serde(default = "default_saml_first_name_attribute")]
    pub first_name: String,

    /// Attribute containing last name
    #[serde(default = "default_saml_last_name_attribute")]
    pub last_name: String,

    /// Attribute containing role/group information
    #[serde(default = "default_saml_role_attribute")]
    pub role: String,

    /// Attribute containing department
    #[serde(default = "default_saml_department_attribute")]
    pub department: String,

    /// Attribute containing job title
    #[serde(default = "default_saml_job_title_attribute")]
    pub job_title: String,
}

impl Default for SamlAttributeMapping {
    fn default() -> Self {
        Self {
            user_id: default_saml_user_id_attribute(),
            username: default_saml_username_attribute(),
            email: default_saml_email_attribute(),
            first_name: default_saml_first_name_attribute(),
            last_name: default_saml_last_name_attribute(),
            role: default_saml_role_attribute(),
            department: default_saml_department_attribute(),
            job_title: default_saml_job_title_attribute(),
        }
    }
}

// Default functions - made public so they can be used from config/types.rs
pub fn default_passkey_storage_path() -> String {
    "_storage/passkeys".to_string()
}

pub fn default_avatars_storage_path() -> String {
    "_storage/avatars".to_string()
}

pub fn default_saml_config_path() -> String {
    "config/saml.json".to_string()
}

#[allow(dead_code)]
pub fn default_session_timeout_minutes() -> u64 {
    20
}

fn default_saml_user_id_attribute() -> String {
    "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier".to_string()
}

fn default_saml_username_attribute() -> String {
    "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name".to_string()
}

fn default_saml_email_attribute() -> String {
    "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress".to_string()
}

fn default_saml_first_name_attribute() -> String {
    "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname".to_string()
}

fn default_saml_last_name_attribute() -> String {
    "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname".to_string()
}

fn default_saml_role_attribute() -> String {
    "http://schemas.microsoft.com/ws/2008/06/identity/claims/role".to_string()
}

fn default_saml_department_attribute() -> String {
    "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/department".to_string()
}

fn default_saml_job_title_attribute() -> String {
    "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/title".to_string()
}

fn default_true() -> bool {
    true
}

impl SamlConfig {
    /// Load SAML configuration from a JSON file
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self, String> {
        let content =
            fs::read_to_string(path.as_ref()).map_err(|e| format!("Failed to read SAML config file: {}", e))?;

        let config: Self =
            serde_json::from_str(&content).map_err(|e| format!("Failed to parse SAML config JSON: {}", e))?;
        config.validate()?;
        Ok(config)
    }

    /// Refuse a `role_mapping` or `default_role` that names a role the gateway does not have.
    pub fn validate(&self) -> Result<(), String> {
        for (idp_role, gateway_role) in &self.role_mapping {
            if crate::auth::types::UserRole::from_config_name(gateway_role).is_none() {
                return Err(format!(
                    "SAML role_mapping entry '{idp_role}' names unknown role '{gateway_role}' (expected administrator, poweruser or user)"
                ));
            }
        }
        if let Some(default_role) = &self.default_role
            && crate::auth::types::UserRole::from_config_name(default_role).is_none()
        {
            return Err(format!(
                "SAML default_role names unknown role '{default_role}' (expected administrator, poweruser or user)"
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config_with(
        role_mapping: serde_json::Value,
        default_role: serde_json::Value,
    ) -> SamlConfig {
        serde_json::from_value(serde_json::json!({
            "idp_entity_id": "idp",
            "idp_sso_url": "https://idp.example/sso",
            "sp_entity_id": "sp",
            "sp_acs_url": "https://sp.example/acs",
            "idp_cert_path": "idp.crt",
            "sp_key_path": null,
            "sp_cert_path": null,
            "role_mapping": role_mapping,
            "default_role": default_role,
        }))
        .unwrap()
    }

    #[test]
    fn a_role_mapping_to_an_unknown_role_is_refused_naming_the_entry() {
        let err = config_with(serde_json::json!({ "gw-admins": "Administrator" }), serde_json::Value::Null)
            .validate()
            .unwrap_err();
        assert!(err.contains("gw-admins") && err.contains("Administrator"), "{err}");
    }

    #[test]
    fn an_unknown_default_role_is_refused() {
        let err = config_with(serde_json::json!({}), serde_json::json!("root"))
            .validate()
            .unwrap_err();
        assert!(err.contains("default_role") && err.contains("root"), "{err}");
    }

    #[test]
    fn known_roles_in_the_mapping_and_default_role_are_accepted() {
        let config = config_with(
            serde_json::json!({ "gw-admins": "administrator", "gw-power": "poweruser", "gw-all": "user" }),
            serde_json::json!("user"),
        );
        assert!(config.validate().is_ok());
    }

    #[test]
    fn the_saml_login_throttle_is_off_unless_saml_json_enables_it() {
        let minimal = serde_json::json!({
            "idp_entity_id": "idp",
            "idp_sso_url": "https://idp.example/sso",
            "sp_entity_id": "sp",
            "sp_acs_url": "https://sp.example/acs",
            "idp_cert_path": "idp.crt",
            "sp_key_path": null,
            "sp_cert_path": null,
        });
        let config: SamlConfig = serde_json::from_value(minimal.clone()).unwrap();
        assert!(!config.login_throttle.enabled);

        let mut enabled = minimal;
        enabled["login_throttle"] = serde_json::json!({ "enabled": true });
        let config: SamlConfig = serde_json::from_value(enabled).unwrap();
        assert!(config.login_throttle.enabled);
        assert_eq!(
            config
                .login_throttle
                .per_ip
                .requests,
            20
        );
    }
}
