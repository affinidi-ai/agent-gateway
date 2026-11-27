//! RBAC configuration loader for rbac.json
//!
//! This module handles loading RBAC (Role-Based Access Control) configuration
//! from the rbac.json file.

use anyhow::{Context, Result};
use std::path::Path;

/// Load RBAC configuration from file
pub fn load_rbac_config<P: AsRef<Path>>(path: P) -> Result<crate::rbac::RbacConfig> {
    let path = path.as_ref();
    let content =
        std::fs::read_to_string(path).with_context(|| format!("Failed to read RBAC config from {}", path.display()))?;

    let config: crate::rbac::RbacConfig = serde_json::from_str(&content)
        .with_context(|| format!("Failed to parse RBAC config from {}", path.display()))?;

    Ok(config)
}

/// Load `rbac.json`, running on the built-in defaults only when the file does not exist.
/// A file that exists but cannot be read or parsed is an error, so a mistake in it never
/// silently replaces the operator's permissions with the defaults.
pub fn load_rbac_config_or_default<P: AsRef<Path>>(path: P) -> Result<crate::rbac::RbacConfig> {
    let path = path.as_ref();
    if !path.exists() {
        tracing::warn!("RBAC config {} not found, using the built-in default permissions", path.display());
        return Ok(crate::rbac::RbacConfig::default());
    }
    load_rbac_config(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_missing_rbac_file_runs_on_the_defaults() {
        let dir = tempfile::tempdir().unwrap();
        let config = load_rbac_config_or_default(dir.path().join("rbac.json")).unwrap();
        assert!(!config.has_permission(&crate::auth::types::UserRole::User, &crate::rbac::Feature::UsersEdit));
    }

    #[test]
    fn an_rbac_file_naming_an_unknown_role_is_an_error_naming_the_permission() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rbac.json");
        std::fs::write(&path, r#"{"permissions": {"users.edit": "Administrator"}}"#).unwrap();
        let err = format!("{:#}", load_rbac_config_or_default(&path).unwrap_err());
        assert!(err.contains("users.edit") && err.contains("'Administrator'"), "{err}");
    }

    #[test]
    fn an_rbac_file_that_is_not_json_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rbac.json");
        std::fs::write(&path, "{not json").unwrap();
        assert!(load_rbac_config_or_default(&path).is_err());
    }

    #[test]
    fn test_parse_rbac_config() {
        let json = r#"{
            "permissions": {
                "users.view": "administrator",
                "users.edit": "administrator",
                "gateways.edit": "poweruser"
            }
        }"#;

        let config: crate::rbac::RbacConfig = serde_json::from_str(json).unwrap();
        assert!(config.permissions.len() >= 3);
        assert_eq!(
            config
                .permissions
                .get("users.view"),
            Some(&"administrator".to_string())
        );
        assert_eq!(
            config
                .permissions
                .get("gateways.edit"),
            Some(&"poweruser".to_string())
        );
    }
}
