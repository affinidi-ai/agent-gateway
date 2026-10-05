//! Encryption initialization helpers

use crate::config::EncryptionConfig;
use crate::encryption::{EncryptionService, KeyManager, KeySource};
use anyhow::{Context, Result};
use tracing::{info, warn};

/// Initialize encryption service from configuration
pub fn init_encryption_service(config: &EncryptionConfig) -> Result<EncryptionService> {
    if !config.enabled {
        info!("Encryption at rest is DISABLED - data will be stored unencrypted");
        return Ok(EncryptionService::disabled());
    }

    info!("Initializing encryption at rest");

    let service = match config.key_source {
        crate::config::KeySourceConfig::Environment => {
            info!("Loading master encryption key from environment variable: {}", config.key_env_var);
            let key_source = KeySource::Environment {
                var_name: config.key_env_var.clone(),
            };
            EncryptionService::new(key_source).context("Failed to initialize encryption service")?
        }
        crate::config::KeySourceConfig::File => {
            let key_file = config
                .key_file
                .as_ref()
                .context("key_file must be specified when using 'file' key source")?;
            info!("Loading master encryption key from file: {}", key_file.display());
            let key_source = KeySource::File { path: key_file.clone() };
            EncryptionService::new(key_source).context("Failed to initialize encryption service")?
        }
        crate::config::KeySourceConfig::AwsKms => {
            let key_id = config
                .kms_key_id
                .as_ref()
                .context("kms_key_id must be specified when using 'aws_kms' key source")?;
            info!("Using AWS KMS per-value envelope encryption (key_id={key_id})");
            let client =
                KeyManager::create_kms_data_keys_client().context("Failed to build AWS KMS client for encryption")?;
            EncryptionService::with_kms(client, key_id.clone(), config.kms_max_concurrent_ops)
        }
        crate::config::KeySourceConfig::Local => {
            warn!(
                "key_source = local performs NO encryption (development only): files are stored as \
                 plaintext envelopes and every encrypt/decrypt is logged under target `{}`",
                crate::encryption::LOCAL_TRACE_TARGET
            );
            EncryptionService::local_trace()
        }
    };

    info!("✓ Encryption at rest initialized successfully");

    Ok(service)
}

/// Print instructions for generating a master key
#[allow(unused)]
pub fn print_master_key_generation_instructions() {
    println!();
    println!("=== Encryption Master Key Setup ===");
    println!();
    println!("To generate a new master encryption key, run:");
    println!();
    println!("  cargo run --bin generate-encryption-key");
    println!();
    println!("Or use this command to generate a key:");
    println!();
    println!("  openssl rand -base64 32");
    println!();
    println!("Then set it in your environment:");
    println!();
    println!("  export AG_MASTER_KEY=\"your-generated-key-here\"");
    println!();
    println!("Or store it in a file and reference it in your configuration:");
    println!();
    println!("  [encryption]");
    println!("  enabled = true");
    println!("  key_source = \"file\"");
    println!("  key_file = \"/path/to/master.key\"");
    println!();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_init_disabled_encryption() {
        let config = EncryptionConfig::default();
        let service = init_encryption_service(&config).unwrap();
        assert!(!service.is_enabled());
    }

    #[test]
    fn test_init_with_raw_key() {
        use std::env;

        unsafe { env::set_var("TEST_ENCRYPTION_KEY", "KioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKio=") };

        let config = EncryptionConfig {
            enabled: true,
            key_source: crate::config::KeySourceConfig::Environment,
            key_env_var: "TEST_ENCRYPTION_KEY".to_string(),
            key_file: None,
            kms_key_id: None,
            kms_max_concurrent_ops: 16,
            field_encryption_enabled: false,
        };

        let service = init_encryption_service(&config).unwrap();
        assert!(service.is_enabled());

        unsafe { env::remove_var("TEST_ENCRYPTION_KEY") };
    }

    #[test]
    fn test_init_missing_env_var_fails_closed() {
        let absent_var = "AG_TEST_ABSENT_MEK_49F2A";
        unsafe { std::env::remove_var(absent_var) };

        let config = EncryptionConfig {
            enabled: true,
            key_source: crate::config::KeySourceConfig::Environment,
            key_env_var: absent_var.to_string(),
            ..Default::default()
        };

        let result = init_encryption_service(&config);
        assert!(result.is_err(), "must fail closed when the KEK env var is absent");
    }

    #[test]
    fn test_init_invalid_env_var_fails_closed() {
        let bad_var = "AG_TEST_BAD_MEK_49F2A";
        unsafe { std::env::set_var(bad_var, "tooshort") };

        let config = EncryptionConfig {
            enabled: true,
            key_source: crate::config::KeySourceConfig::Environment,
            key_env_var: bad_var.to_string(),
            ..Default::default()
        };

        let result = init_encryption_service(&config);
        assert!(result.is_err(), "must fail closed when the KEK env var is too short / invalid");
        unsafe { std::env::remove_var(bad_var) };
    }

    #[test]
    fn test_init_local_trace_needs_no_key_material() {
        let config = EncryptionConfig {
            enabled: true,
            key_source: crate::config::KeySourceConfig::Local,
            key_env_var: "AG_TEST_ABSENT_FOR_LOCAL_TRACE".to_string(),
            ..Default::default()
        };

        let service = init_encryption_service(&config).expect("local trace must not require a key");
        assert!(service.is_enabled());
        let sealed = service
            .encrypt_field("dev")
            .unwrap();
        assert!(sealed.starts_with("ENC[0::"), "{sealed}");
    }

    #[test]
    fn test_init_aws_kms_missing_kms_key_id_fails_closed() {
        let config = EncryptionConfig {
            enabled: true,
            key_source: crate::config::KeySourceConfig::AwsKms,
            kms_key_id: None,
            ..Default::default()
        };

        let err = init_encryption_service(&config).expect_err("aws_kms without kms_key_id must fail closed");
        assert!(
            err.to_string()
                .contains("kms_key_id"),
            "error must name the missing kms_key_id, got: {err}"
        );
    }
}
