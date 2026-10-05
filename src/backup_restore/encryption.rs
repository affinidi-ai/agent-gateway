//! Backup encryption using AES-256-GCM
//!
//! The backup key is REQUIRED and sourced at runtime from `backup_encryption_key`
//! — an `env://VAR` reference (recommended), a literal 64-char hex string, or a
//! `file://path` reference. There is no committed default key. The `aws_secrets://`
//! and `aws_parameter_store://` schemes are NOT supported for backup-key sources.
//! Temporary legacy keys require the explicit optional `legacy_backup_encryption_keys`
//! configuration field; an environment variable alone does not enable compatibility.
//! AES-256-GCM provides confidentiality + integrity (authenticated encryption).
//!
//! Encrypted format: `[12-byte nonce][ciphertext + 16-byte GCM tag][8-byte magic]`

use crate::encryption::aes_gcm::AesGcmEncryptor;
use anyhow::Context;

/// Magic trailer identifying an encrypted backup file.
const MAGIC: &[u8; 8] = b"TGWENC\0\0";

/// Minimum encrypted file size: 12 (nonce) + 16 (GCM tag) + 8 (magic) = 36.
const MIN_ENCRYPTED_LEN: usize = 12 + 16 + 8;

const MAX_LEGACY_BACKUP_KEYS: usize = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackupKeySource {
    Current,
    Legacy,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecryptedBackup {
    pub bytes: Vec<u8>,
    pub key_source: BackupKeySource,
}

/// Resolve the required 32-byte backup encryption key.
///
/// `config_value` is the `backup_encryption_key` bootstrap field: an `env://VAR`
/// reference (recommended), a literal 64-char hex string, or a `file://path`
/// reference. Fails closed: returns an error when the value is empty, uses an
/// unsupported source, or does not resolve to exactly 32 bytes. There is no
/// fallback key.
///
/// `aws_secrets://` and `aws_parameter_store://` are explicitly rejected — those
/// sources are not supported for the backup key.
pub async fn resolve_backup_key(config_value: &str) -> anyhow::Result<[u8; 32]> {
    let reference = config_value.trim();
    if reference.is_empty() {
        anyhow::bail!("backup_encryption_key is required — set it to env://VAR or a 64-char hex key");
    }
    if reference.starts_with("aws_secrets://") || reference.starts_with("aws_parameter_store://") {
        anyhow::bail!(
            "backup_encryption_key does not support aws_secrets:// or aws_parameter_store:// — \
             use env://VAR, a 64-char hex key, or file://path"
        );
    }
    let resolved = crate::config::loaders::load(reference)
        .await
        .map_err(|e| anyhow::anyhow!("failed to resolve backup_encryption_key: {e}"))?;
    decode_hex_key(resolved.trim())
}

/// Decode a 64-char hex string into a 32-byte key.
fn decode_hex_key(hex_str: &str) -> anyhow::Result<[u8; 32]> {
    let bytes = hex::decode(hex_str).context("backup_encryption_key must be a 64-char hex string")?;
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("backup_encryption_key must decode to exactly 32 bytes"))
}

/// Encrypt raw zip bytes into the encrypted backup format.
///
/// Returns: `[nonce (12)][ciphertext + tag (N+16)][magic (8)]`
pub fn encrypt_backup(
    key: &[u8; 32],
    zip_bytes: &[u8],
) -> anyhow::Result<Vec<u8>> {
    let encryptor = AesGcmEncryptor::new();
    let encrypted = encryptor
        .encrypt(key, zip_bytes)
        .map_err(|e| anyhow::anyhow!("Backup encryption failed: {}", e))?;

    let mut output = Vec::with_capacity(encrypted.len() + MAGIC.len());
    output.extend_from_slice(&encrypted);
    output.extend_from_slice(MAGIC);
    Ok(output)
}

/// Check whether raw bytes represent an encrypted backup (has the magic trailer).
pub fn is_encrypted_backup(data: &[u8]) -> bool {
    data.len() >= MIN_ENCRYPTED_LEN && &data[data.len() - 8..] == MAGIC
}

/// Decrypt an encrypted backup file back to raw zip bytes.
///
/// Input: `[nonce (12)][ciphertext + tag (N+16)][magic (8)]`
/// Returns the decrypted zip bytes.
pub fn decrypt_backup(
    key: &[u8; 32],
    data: &[u8],
) -> anyhow::Result<Vec<u8>> {
    if !is_encrypted_backup(data) {
        anyhow::bail!("Not an encrypted backup (missing TGWENC magic trailer)");
    }

    // Strip magic trailer
    let encrypted = &data[..data.len() - 8];

    let encryptor = AesGcmEncryptor::new();
    let decrypted = encryptor
        .decrypt(key, encrypted)
        .map_err(|e| anyhow::anyhow!("Backup decryption failed (wrong key or tampered data): {}", e))?;

    // Sanity check: decrypted data should be a valid zip (starts with PK)
    if decrypted.len() < 4 || decrypted[0..2] != [0x50, 0x4B] {
        anyhow::bail!("Decrypted backup is not a valid ZIP archive");
    }

    Ok(decrypted)
}

pub fn decrypt_backup_with_keys(
    current: &[u8; 32],
    legacy: &[[u8; 32]],
    data: &[u8],
) -> anyhow::Result<DecryptedBackup> {
    match decrypt_backup(current, data) {
        Ok(bytes) => Ok(DecryptedBackup {
            bytes,
            key_source: BackupKeySource::Current,
        }),
        Err(current_error) => {
            for key in legacy {
                if let Ok(bytes) = decrypt_backup(key, data) {
                    return Ok(DecryptedBackup {
                        bytes,
                        key_source: BackupKeySource::Legacy,
                    });
                }
            }
            Err(current_error)
        }
    }
}

pub fn resolve_legacy_backup_keys(config_value: Option<&str>) -> anyhow::Result<Vec<[u8; 32]>> {
    resolve_legacy_backup_keys_with(
        config_value,
        |name| std::env::var(name).map_err(|error| error.to_string()),
        |path| std::fs::read_to_string(path).map_err(|error| error.to_string()),
    )
}

fn resolve_legacy_backup_keys_with(
    config_value: Option<&str>,
    env_loader: impl FnOnce(&str) -> Result<String, String>,
    file_loader: impl FnOnce(&str) -> Result<String, String>,
) -> anyhow::Result<Vec<[u8; 32]>> {
    let Some(reference) = config_value else {
        return Ok(Vec::new());
    };
    let reference = reference.trim();
    if reference.is_empty() {
        anyhow::bail!("legacy_backup_encryption_keys must not be empty when configured");
    }

    let resolved = if let Some(name) = reference.strip_prefix("env://") {
        if name.is_empty() {
            anyhow::bail!("legacy_backup_encryption_keys env reference is empty");
        }
        env_loader(name)
            .map_err(|_| anyhow::anyhow!("failed to resolve legacy_backup_encryption_keys environment reference"))?
    } else if let Some(path) = reference.strip_prefix("file://") {
        if path.is_empty() {
            anyhow::bail!("legacy_backup_encryption_keys file reference is empty");
        }
        file_loader(path)
            .map_err(|_| anyhow::anyhow!("failed to resolve legacy_backup_encryption_keys file reference"))?
    } else if reference.starts_with("aws_secrets://") || reference.starts_with("aws_parameter_store://") {
        anyhow::bail!(
            "legacy_backup_encryption_keys does not support direct AWS source references; use env://VAR, file://path, or a literal key list"
        );
    } else {
        reference.to_owned()
    };

    parse_legacy_backup_keys(&resolved)
}

fn parse_legacy_backup_keys(value: &str) -> anyhow::Result<Vec<[u8; 32]>> {
    let values: Vec<_> = value
        .split(',')
        .map(str::trim)
        .collect();
    if values.is_empty()
        || values.len() > MAX_LEGACY_BACKUP_KEYS
        || values
            .iter()
            .any(|value| value.is_empty())
    {
        anyhow::bail!(
            "legacy_backup_encryption_keys must resolve to between 1 and {MAX_LEGACY_BACKUP_KEYS} comma-separated keys"
        );
    }
    values
        .into_iter()
        .map(|value| decode_hex_key(value).context("legacy_backup_encryption_keys contains an invalid key"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> [u8; 32] {
        [0xAA; 32]
    }

    fn sample_zip() -> Vec<u8> {
        // Minimal valid zip (empty archive)
        use std::io::Cursor;
        use zip::write::{FileOptions, SimpleFileOptions, ZipWriter};

        let cursor = Cursor::new(Vec::new());
        let mut zip = ZipWriter::new(cursor);
        let options: SimpleFileOptions = FileOptions::default();
        zip.start_file("test.txt", options)
            .unwrap();
        use std::io::Write;
        zip.write_all(b"hello")
            .unwrap();
        zip.finish()
            .unwrap()
            .into_inner()
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let key = test_key();
        let zip = sample_zip();

        let encrypted = encrypt_backup(&key, &zip).unwrap();

        // Must end with magic
        assert!(is_encrypted_backup(&encrypted));
        assert_eq!(&encrypted[encrypted.len() - 8..], MAGIC);

        // Must NOT start with PK (it's encrypted)
        assert_ne!(&encrypted[0..2], &[0x50, 0x4B]);

        let decrypted = decrypt_backup(&key, &encrypted).unwrap();
        assert_eq!(decrypted, zip);
    }

    #[test]
    fn wrong_key_fails_decryption() {
        let key = test_key();
        let zip = sample_zip();

        let encrypted = encrypt_backup(&key, &zip).unwrap();

        let wrong_key = [0xBB; 32];
        let result = decrypt_backup(&wrong_key, &encrypted);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("wrong key or tampered")
        );
    }

    #[test]
    fn tampered_data_fails_decryption() {
        let key = test_key();
        let zip = sample_zip();

        let mut encrypted = encrypt_backup(&key, &zip).unwrap();

        // Tamper with a byte in the ciphertext (after nonce, before magic)
        if encrypted.len() > 20 {
            encrypted[15] ^= 0xFF;
        }

        let result = decrypt_backup(&key, &encrypted);
        assert!(result.is_err());
    }

    #[test]
    fn nonce_and_authentication_tag_tampering_are_rejected() {
        let key = test_key();
        let zip = sample_zip();

        let mut nonce_tampered = encrypt_backup(&key, &zip).unwrap();
        nonce_tampered[0] ^= 0xff;
        assert!(decrypt_backup(&key, &nonce_tampered).is_err());

        let mut tag_tampered = encrypt_backup(&key, &zip).unwrap();
        let final_tag_byte = tag_tampered.len() - MAGIC.len() - 1;
        tag_tampered[final_tag_byte] ^= 0xff;
        assert!(decrypt_backup(&key, &tag_tampered).is_err());
    }

    #[test]
    fn non_encrypted_data_rejected() {
        let key = test_key();
        let zip = sample_zip();

        // Raw zip without encryption should be rejected
        assert!(!is_encrypted_backup(&zip));
        let result = decrypt_backup(&key, &zip);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn resolve_key_from_literal_hex() {
        let hex_key = "aa".repeat(32); // 64 hex chars = 32 bytes of 0xAA
        let key = resolve_backup_key(&hex_key)
            .await
            .unwrap();
        assert_eq!(key, [0xAA; 32]);
    }

    #[tokio::test]
    async fn resolve_key_missing_is_error() {
        assert!(
            resolve_backup_key("")
                .await
                .is_err()
        );
        assert!(
            resolve_backup_key("   ")
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn resolve_key_invalid_hex_is_error() {
        // Not hex.
        assert!(
            resolve_backup_key("not-hex")
                .await
                .is_err()
        );
        // Valid hex but wrong length (2 bytes, not 32).
        assert!(
            resolve_backup_key("aabb")
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn resolve_key_rejects_aws_sources() {
        // The AWS-backed loader schemes are not supported for the backup key.
        assert!(
            resolve_backup_key("aws_secrets://agent-gateway/backup-key")
                .await
                .is_err()
        );
        assert!(
            resolve_backup_key("aws_parameter_store://agent-gateway/backup-key")
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn resolve_key_from_env_uri() {
        let var = "AG_TEST_BACKUP_KEY_RESOLVE";
        // SAFETY: dedicated test-only var, set and read within this test.
        unsafe { std::env::set_var(var, "bb".repeat(32)) };
        let key = resolve_backup_key(&format!("env://{var}"))
            .await
            .unwrap();
        unsafe { std::env::remove_var(var) };
        assert_eq!(key, [0xBB; 32]);
    }

    #[test]
    fn decrypt_with_explicit_legacy_keys_reports_source() {
        let legacy = [0xCC; 32];
        let zip = sample_zip();
        let encrypted = encrypt_backup(&legacy, &zip).unwrap();

        let decrypted = decrypt_backup_with_keys(&[0x11; 32], &[legacy], &encrypted).unwrap();

        assert_eq!(decrypted.bytes, zip);
        assert_eq!(decrypted.key_source, BackupKeySource::Legacy);
    }

    #[test]
    fn decrypt_tries_bounded_legacy_keys_in_order() {
        let zip = sample_zip();
        let encrypted = encrypt_backup(&[0xDD; 32], &zip).unwrap();

        let decrypted = decrypt_backup_with_keys(&[0x11; 32], &[[0xCC; 32], [0xDD; 32]], &encrypted).unwrap();

        assert_eq!(decrypted.bytes, zip);
        assert_eq!(decrypted.key_source, BackupKeySource::Legacy);
    }

    #[test]
    fn missing_legacy_key_configuration_disables_compatibility_without_reading_environment() {
        let keys = resolve_legacy_backup_keys_with(
            None,
            |_| panic!("must not read environment"),
            |_| panic!("must not read file"),
        )
        .unwrap();

        assert!(keys.is_empty());
    }

    #[test]
    fn legacy_keys_resolve_from_the_configured_environment_reference() {
        let keys = resolve_legacy_backup_keys_with(
            Some("env://AG_LEGACY_BACKUP_KEYS"),
            |name| {
                assert_eq!(name, "AG_LEGACY_BACKUP_KEYS");
                Ok(format!("{},{}", "cc".repeat(32), "dd".repeat(32)))
            },
            |_| panic!("must not read file"),
        )
        .unwrap();

        assert_eq!(keys, vec![[0xCC; 32], [0xDD; 32]]);
    }

    #[test]
    fn legacy_keys_resolve_from_the_configured_file_reference() {
        let keys = resolve_legacy_backup_keys_with(
            Some("file:///run/secrets/legacy-backup-keys"),
            |_| panic!("must not read environment"),
            |path| {
                assert_eq!(path, "/run/secrets/legacy-backup-keys");
                Ok("ee".repeat(32))
            },
        )
        .unwrap();

        assert_eq!(keys, vec![[0xEE; 32]]);
    }

    #[test]
    fn legacy_key_configuration_rejects_direct_aws_references() {
        for reference in ["aws_secrets://legacy-keys", "aws_parameter_store://legacy-keys"] {
            assert!(resolve_legacy_backup_keys(Some(reference)).is_err());
        }
    }

    #[test]
    fn explicitly_empty_legacy_key_configuration_fails_closed() {
        assert!(resolve_legacy_backup_keys(Some("  ")).is_err());
        assert!(parse_legacy_backup_keys("  ").is_err());
    }

    #[test]
    fn legacy_key_configuration_rejects_more_than_four_keys() {
        let value = std::iter::repeat_n("aa".repeat(32), 5)
            .collect::<Vec<_>>()
            .join(",");
        assert!(parse_legacy_backup_keys(&value).is_err());
    }

    #[test]
    fn legacy_key_configuration_parses_ordered_keys() {
        let value = format!("{},{}", "cc".repeat(32), "dd".repeat(32));
        let keys = parse_legacy_backup_keys(&value).unwrap();
        assert_eq!(keys, vec![[0xCC; 32], [0xDD; 32]]);
    }
}
