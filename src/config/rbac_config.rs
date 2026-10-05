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

#[cfg(test)]
mod tests {
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
