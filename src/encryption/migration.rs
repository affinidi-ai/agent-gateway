//! One-shot boot migration for residual field-level `ENC[...]` values.
//!
//! Field-level encryption has been removed in favour of whole-file encryption.
//! Stores written by an earlier build may still hold `ENC[...]` string values
//! inside readable `.json` files. This sweep runs once at boot (before any store
//! is loaded into a model) and rewrites those files as plaintext JSON, decrypting
//! each `ENC[...]` value with the global `EncryptionService`. Whole-file
//! encryption re-wraps the file on the next save.
//!
//! The sweep is idempotent: a file with no `ENC[...]` value is left byte-for-byte
//! untouched, and whole-file `.json.enc` blobs are skipped entirely.

use std::path::Path;

use serde_json::Value;
use tracing::{info, warn};

use crate::config::EncryptionConfig;
use crate::encryption::{EncryptionService, global};

/// Decrypt residual field-level `ENC[...]` values under `storage_root` to
/// plaintext, in place. No-op when encryption is disabled or no service is
/// available.
pub fn migrate_field_encrypted_values(
    storage_root: &Path,
    encryption: &EncryptionConfig,
) {
    if !encryption.enabled {
        return;
    }
    let service = match global::get_encryption_service() {
        Some(service) => service,
        None => return,
    };
    if !storage_root.is_dir() {
        return;
    }
    let migrated = migrate_dir(storage_root, &service);
    if migrated > 0 {
        info!(
            "Encryption migration: rewrote {} file(s) with residual field-level ENC[...] values to plaintext",
            migrated
        );
    }
}

fn migrate_dir(
    dir: &Path,
    service: &EncryptionService,
) -> usize {
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) => {
            warn!("Encryption migration: cannot read {}: {}", dir.display(), e);
            return 0;
        }
    };
    let mut migrated = 0;
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            migrated += migrate_dir(&path, service);
            continue;
        }
        if path
            .extension()
            .and_then(|e| e.to_str())
            != Some("json")
        {
            continue;
        }
        if migrate_file(&path, service) {
            migrated += 1;
        }
    }
    migrated
}

fn migrate_file(
    path: &Path,
    service: &EncryptionService,
) -> bool {
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(e) => {
            warn!("Encryption migration: cannot read {}: {}", path.display(), e);
            return false;
        }
    };
    let mut value: Value = match serde_json::from_slice(&bytes) {
        Ok(value) => value,
        Err(_) => return false,
    };
    let mut changed = false;
    decrypt_value(&mut value, service, &mut changed);
    if !changed {
        return false;
    }
    let serialized = match serde_json::to_vec_pretty(&value) {
        Ok(serialized) => serialized,
        Err(e) => {
            warn!("Encryption migration: cannot re-serialize {}: {}", path.display(), e);
            return false;
        }
    };
    match std::fs::write(path, serialized) {
        Ok(()) => true,
        Err(e) => {
            warn!("Encryption migration: cannot write {}: {}", path.display(), e);
            false
        }
    }
}

fn decrypt_value(
    value: &mut Value,
    service: &EncryptionService,
    changed: &mut bool,
) {
    match value {
        Value::String(s) if s.starts_with("ENC[") => match service.decrypt_field(s) {
            Ok(plaintext) if &plaintext != s => {
                *s = plaintext;
                *changed = true;
            }
            Ok(_) => {}
            Err(e) => warn!("Encryption migration: leaving value verbatim, decrypt failed: {}", e),
        },
        Value::Array(items) => {
            for item in items.iter_mut() {
                decrypt_value(item, service, changed);
            }
        }
        Value::Object(map) => {
            for (_key, item) in map.iter_mut() {
                decrypt_value(item, service, changed);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encryption::KeySource;

    #[test]
    fn migrates_field_encrypted_value_to_plaintext() {
        let service = EncryptionService::new(KeySource::Raw { key: [9u8; 32] }).unwrap();
        let config = EncryptionConfig {
            enabled: true,
            ..Default::default()
        };
        global::set_test_encryption(config.clone(), service.clone());

        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("sec-1.json");
        let ciphertext = service
            .encrypt_field("super-secret-value")
            .unwrap();
        assert!(ciphertext.starts_with("ENC["));
        let record = serde_json::json!({
            "id": "sec-1",
            "value": ciphertext,
        });
        std::fs::write(&file, serde_json::to_vec_pretty(&record).unwrap()).unwrap();

        migrate_field_encrypted_values(dir.path(), &config);

        let on_disk = std::fs::read_to_string(&file).unwrap();
        assert!(!on_disk.contains("ENC["), "field-encrypted value must be rewritten to plaintext: {on_disk}");
        let parsed: Value = serde_json::from_str(&on_disk).unwrap();
        assert_eq!(parsed["value"], "super-secret-value");
    }

    #[test]
    fn leaves_plaintext_file_untouched() {
        let service = EncryptionService::new(KeySource::Raw { key: [9u8; 32] }).unwrap();
        let config = EncryptionConfig {
            enabled: true,
            ..Default::default()
        };
        global::set_test_encryption(config.clone(), service);

        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("plain.json");
        let original = serde_json::to_vec_pretty(&serde_json::json!({ "value": "plain" })).unwrap();
        std::fs::write(&file, &original).unwrap();

        migrate_field_encrypted_values(dir.path(), &config);

        assert_eq!(std::fs::read(&file).unwrap(), original, "a file with no ENC[...] must be untouched");
    }
}
