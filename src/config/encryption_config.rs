//! Encryption at rest configuration

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Encryption at rest configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptionConfig {
    /// Whether encryption is enabled
    #[serde(default)]
    pub enabled: bool,

    /// Source for the master encryption key
    #[serde(default)]
    pub key_source: KeySourceConfig,

    /// Environment variable name for master key (when using 'environment' source)
    #[serde(default = "default_key_env_var")]
    pub key_env_var: String,

    /// File path for master key (when using 'file' source)
    pub key_file: Option<PathBuf>,

    /// AWS KMS key ID (when using 'aws_kms' source)
    pub kms_key_id: Option<String>,

    /// Whether encryption is enabled for individual fields fo entities.
    /// TODO: once pub key is implemented, add dedicated key per field-encryption.
    /// Note: field-level encryption is disabled when filesystem encryption is used.
    #[serde(default)]
    pub field_encryption_enabled: bool,

    /// Maximum number of concurrent AWS KMS operations (GenerateDataKey / Decrypt)
    /// allowed in flight when `key_source = aws_kms`. Bounds pressure on the shared
    /// per-region KMS request quota. Ignored for non-KMS key sources.
    #[serde(default = "default_kms_max_concurrent_ops")]
    pub kms_max_concurrent_ops: usize,
}

impl Default for EncryptionConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            key_source: KeySourceConfig::Environment,
            key_env_var: default_key_env_var(),
            key_file: None,
            kms_key_id: None,
            kms_max_concurrent_ops: default_kms_max_concurrent_ops(),
            field_encryption_enabled: false,
        }
    }
}

/// Source for the master encryption key
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum KeySourceConfig {
    /// Load key from environment variable
    #[default]
    Environment,

    /// Load key from file
    File,

    /// Use AWS KMS (per-value envelope encryption; requires `kms_key_id`)
    AwsKms,

    /// Development only: no encryption. Files are written as pass-through
    /// envelopes and every encrypt/decrypt is logged with file name and
    /// fingerprint, so the whole-file code path can be observed locally.
    Local,
}

fn default_key_env_var() -> String {
    "AG_MASTER_KEY".to_string()
}

fn default_kms_max_concurrent_ops() -> usize {
    16
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = EncryptionConfig::default();
        assert!(!config.enabled);
        assert_eq!(config.key_source, KeySourceConfig::Environment);
        assert_eq!(config.key_env_var, "AG_MASTER_KEY");
    }

    #[test]
    fn test_serialize_deserialize() {
        let config = EncryptionConfig {
            enabled: true,
            key_source: KeySourceConfig::Environment,
            key_env_var: "MY_KEY".to_string(),
            key_file: None,
            kms_key_id: None,
            kms_max_concurrent_ops: 8,
            field_encryption_enabled: false,
        };

        let json = serde_json::to_string(&config).unwrap();
        let deserialized: EncryptionConfig = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.enabled, config.enabled);
        assert_eq!(deserialized.key_source, config.key_source);
        assert_eq!(deserialized.key_env_var, config.key_env_var);
        assert_eq!(deserialized.kms_max_concurrent_ops, config.kms_max_concurrent_ops);
    }

    #[test]
    fn test_default_kms_max_concurrent_ops() {
        assert_eq!(EncryptionConfig::default().kms_max_concurrent_ops, 16);
    }

    #[test]
    fn test_missing_kms_max_concurrent_ops_defaults_to_16() {
        let json = r#"{
            "enabled": true,
            "key_source": "aws_kms",
            "kms_key_id": "arn:aws:kms:us-east-1:111122223333:key/abc"
        }"#;

        let deserialized: EncryptionConfig = serde_json::from_str(json).unwrap();
        assert_eq!(deserialized.kms_max_concurrent_ops, 16);
        assert_eq!(deserialized.key_source, KeySourceConfig::AwsKms);
    }

    #[test]
    fn test_key_source_wire_tokens() {
        assert_eq!(serde_json::to_string(&KeySourceConfig::Environment).unwrap(), "\"environment\"");
        assert_eq!(serde_json::to_string(&KeySourceConfig::File).unwrap(), "\"file\"");
        assert_eq!(serde_json::to_string(&KeySourceConfig::AwsKms).unwrap(), "\"aws_kms\"");
        assert_eq!(serde_json::from_str::<KeySourceConfig>("\"aws_kms\"").unwrap(), KeySourceConfig::AwsKms);
        assert_eq!(serde_json::to_string(&KeySourceConfig::Local).unwrap(), "\"local\"");
        assert_eq!(serde_json::from_str::<KeySourceConfig>("\"local\"").unwrap(), KeySourceConfig::Local);
    }
}
