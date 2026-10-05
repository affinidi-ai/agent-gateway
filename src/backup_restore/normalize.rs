//! KEK-decrypt normalization for portable backups.
//!
//! On export, every field-encrypted value (`ENC[...]`) is decrypted to plaintext
//! so the archive is independent of this node's field-encryption key (KEK) and
//! can be restored on any node holding the backup encryption key (BEK). The whole
//! archive is BEK-encrypted afterwards by the existing `encryption` module.
//!
//! Decryption uses a service that can read existing `ENC[...]` values even when
//! encryption-at-rest is disabled (`enabled = false`) — the process-global service
//! is a pass-through in that mode, so a key-source-backed service is built instead
//! (see [`backup_decryption_service`]).

use serde_json::Value;
use tracing::warn;

use crate::encryption::EncryptionService;

/// Decrypt every `ENC[...]` string value in a `.json` storage file for a portable
/// backup, using the provided field-encryption service.
///
/// Returns the input bytes **unchanged** when the path is not a `.json` file, the
/// content is not valid JSON, or nothing was decrypted (so a disabled-encryption
/// export is byte-identical to a verbatim copy).
pub(crate) fn normalize_file_for_backup(
    relative_path: &str,
    bytes: &[u8],
    service: Option<&EncryptionService>,
) -> Vec<u8> {
    let decrypt = |value: &str| decrypt_with(service, value);
    normalize_file_with(relative_path, bytes, &decrypt)
}

/// Decide the ZIP entry (name + bytes) for one storage file on the portable-backup
/// export path.
///
/// - A whole-file `*.json.enc` blob is decrypted to plaintext and re-nested under the
///   same name with `.enc` stripped (`id.json.enc` -> `id.json`), so the archive
///   contains no encrypted files. If it cannot be decrypted (no/wrong key, corrupt),
///   the blob is kept **verbatim under its original `.json.enc` name** with a warning
///   — the export never aborts and never drops data (R4 policy B).
/// - A `.json` file still has any residual field-level `ENC[...]` value flattened.
/// - Any other file (including other `*.enc`) is copied byte-for-byte.
pub(crate) fn backup_entry_for_file(
    relative_path: &str,
    bytes: &[u8],
    service: Option<&EncryptionService>,
) -> (String, Vec<u8>) {
    if relative_path.ends_with(".json.enc") {
        return match decrypt_whole_file(service, bytes) {
            Some(plaintext) => {
                let stripped = relative_path
                    .strip_suffix(".enc")
                    .unwrap_or(relative_path)
                    .to_string();
                (stripped, plaintext)
            }
            None => {
                warn!(
                    "Portable backup: could not decrypt whole-file blob {} — keeping it encrypted \
                     in the archive. Configure the encryption key source to make this backup portable.",
                    relative_path
                );
                (relative_path.to_string(), bytes.to_vec())
            }
        };
    }

    let content = normalize_file_for_backup(relative_path, bytes, service);
    (relative_path.to_string(), content)
}

/// Decrypt a whole-file `ENC[...]` envelope to its plaintext bytes. Returns `None`
/// (leave verbatim) when no service is available, the bytes are not valid UTF-8, or
/// decryption fails.
fn decrypt_whole_file(
    service: Option<&EncryptionService>,
    bytes: &[u8],
) -> Option<Vec<u8>> {
    let service = service?;
    let envelope = String::from_utf8(bytes.to_vec()).ok()?;
    match service.decrypt_string(envelope) {
        Ok(plaintext) => Some(plaintext.into_bytes()),
        Err(e) => {
            warn!("Portable backup: whole-file decrypt failed: {}", e);
            None
        }
    }
}

/// Build the decryption service used to normalize a portable backup.
///
/// Delegates to the encryption module, which returns the live service when field
/// encryption is active and otherwise builds one from the configured key source so
/// existing `ENC[...]` values can still be decrypted after encryption-at-rest is
/// disabled. `None` means no key material is available.
pub(crate) fn backup_decryption_service() -> Option<EncryptionService> {
    crate::encryption::global::build_backup_decryption_service()
}

/// Decrypt one `ENC[...]` value via the given service. Returns `None` (leave the
/// value verbatim) when no service is available or decryption fails — a backup must
/// never abort or silently drop data over one unreadable field.
fn decrypt_with(
    service: Option<&EncryptionService>,
    value: &str,
) -> Option<String> {
    let service = service?;
    match service.decrypt_field(value) {
        Ok(plaintext) => Some(plaintext),
        Err(e) => {
            warn!("Backup normalize: leaving field-encrypted value verbatim, decrypt failed: {}", e);
            None
        }
    }
}

fn normalize_file_with(
    relative_path: &str,
    bytes: &[u8],
    decrypt: &dyn Fn(&str) -> Option<String>,
) -> Vec<u8> {
    if !relative_path.ends_with(".json") {
        return bytes.to_vec();
    }

    let mut value: Value = match serde_json::from_slice(bytes) {
        Ok(value) => value,
        Err(_) => return bytes.to_vec(),
    };

    let mut changed = false;
    normalize_value(&mut value, decrypt, &mut changed);
    if !changed {
        return bytes.to_vec();
    }

    match serde_json::to_vec_pretty(&value) {
        Ok(serialized) => serialized,
        Err(_) => bytes.to_vec(),
    }
}

fn normalize_value(
    value: &mut Value,
    decrypt: &dyn Fn(&str) -> Option<String>,
    changed: &mut bool,
) {
    match value {
        Value::String(s) => {
            if s.starts_with("ENC[")
                && let Some(plaintext) = decrypt(s)
                && &plaintext != s
            {
                *s = plaintext;
                *changed = true;
            }
        }
        Value::Array(items) => {
            for item in items.iter_mut() {
                normalize_value(item, decrypt, changed);
            }
        }
        Value::Object(map) => {
            for (_key, item) in map.iter_mut() {
                normalize_value(item, decrypt, changed);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Fake decryptor: `ENC[good:<plaintext>]` -> `<plaintext>`, anything else
    /// (unknown / undecryptable) -> `None` (leave verbatim).
    fn fake_decrypt(value: &str) -> Option<String> {
        value
            .strip_prefix("ENC[good:")
            .and_then(|rest| rest.strip_suffix(']'))
            .map(|plaintext| plaintext.to_string())
    }

    fn normalize(
        path: &str,
        bytes: &[u8],
    ) -> Vec<u8> {
        normalize_file_with(path, bytes, &fake_decrypt)
    }

    #[test]
    fn enc_string_becomes_plaintext() {
        let input = br#"{"secret":"ENC[good:hunter2]"}"#;
        let out = normalize("identity/a.json", input);
        let parsed: Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(parsed["secret"], Value::String("hunter2".to_string()));
    }

    #[test]
    fn nested_and_array_enc_are_handled() {
        let input = br#"{"a":{"b":"ENC[good:x]"},"c":["ENC[good:y]","plain"]}"#;
        let out = normalize("secrets/s.json", input);
        let parsed: Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(parsed["a"]["b"], Value::String("x".to_string()));
        assert_eq!(parsed["c"][0], Value::String("y".to_string()));
        assert_eq!(parsed["c"][1], Value::String("plain".to_string()));
    }

    #[test]
    fn non_enc_string_is_untouched_and_byte_identical() {
        let input = br#"{"name":"plain","count":3}"#;
        let out = normalize("identity/a.json", input);
        assert_eq!(out, input.to_vec());
    }

    #[test]
    fn non_json_file_is_byte_identical() {
        let input = b"this is not json ENC[good:x]";
        assert_eq!(normalize("certs/leaf.pem", input), input.to_vec());
        // Even with a `.json` extension, invalid JSON is returned verbatim.
        assert_eq!(normalize("broken.json", input), input.to_vec());
    }

    #[test]
    fn wrong_extension_is_byte_identical_even_if_valid_json() {
        let input = br#"{"secret":"ENC[good:hunter2]"}"#;
        // A `.json.enc` whole-file blob or any non-`.json` path is left verbatim.
        assert_eq!(normalize("secrets/s.json.enc", input), input.to_vec());
    }

    #[test]
    fn undecryptable_enc_value_is_preserved_verbatim() {
        let input = br#"{"secret":"ENC[unknown-format]"}"#;
        // Nothing decrypts -> byte-identical (never abort, never drop data).
        assert_eq!(normalize("secrets/s.json", input), input.to_vec());
    }

    #[test]
    fn mixed_decryptable_and_not_only_changes_the_decryptable() {
        let input = br#"{"ok":"ENC[good:v]","bad":"ENC[nope]"}"#;
        let out = normalize("secrets/s.json", input);
        let parsed: Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(parsed["ok"], Value::String("v".to_string()));
        assert_eq!(parsed["bad"], Value::String("ENC[nope]".to_string()));
    }

    #[test]
    fn service_backed_normalize_decrypts_enc_values() {
        use crate::encryption::{EncryptionService, KeySource};

        // A value encrypted while encryption-at-rest was enabled.
        let service = EncryptionService::new(KeySource::Raw { key: [7u8; 32] }).unwrap();
        let ciphertext = service
            .encrypt_field("hunter2")
            .unwrap();
        assert!(ciphertext.starts_with("ENC["));

        let input = format!(r#"{{"secret":"{ciphertext}"}}"#);
        let out = normalize_file_for_backup("secrets/s.json", input.as_bytes(), Some(&service));
        let parsed: Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(parsed["secret"], Value::String("hunter2".to_string()));
    }

    #[test]
    fn disabled_service_leaves_enc_verbatim() {
        // Reproduces the reported bug: a disabled pass-through service returns
        // ciphertext unchanged, so `ENC[...]` survives into the archive. The fix is
        // to hand `normalize_file_for_backup` a decryption-capable service instead.
        let service = crate::encryption::EncryptionService::disabled();
        let input = br#"{"secret":"ENC[v1:whatever]"}"#;
        let out = normalize_file_for_backup("secrets/s.json", input, Some(&service));
        assert_eq!(out, input.to_vec());
    }

    #[test]
    fn no_service_leaves_enc_verbatim() {
        let input = br#"{"secret":"ENC[v1:whatever]"}"#;
        let out = normalize_file_for_backup("secrets/s.json", input, None);
        assert_eq!(out, input.to_vec());
    }

    #[test]
    fn whole_file_enc_blob_is_decrypted_and_renamed_to_json() {
        use crate::encryption::{EncryptionService, KeySource};

        let service = EncryptionService::new(KeySource::Raw { key: [9u8; 32] }).unwrap();
        let plaintext = r#"{"private_key":"abc","did":"did:key:z6Mk"}"#;
        // A whole-file `.json.enc` blob is the ENC[...] envelope of the file's bytes.
        let envelope = service
            .encrypt_string(plaintext.to_string())
            .unwrap();
        assert!(envelope.starts_with("ENC["));

        let (name, out) = backup_entry_for_file("identity/x.json.enc", envelope.as_bytes(), Some(&service));
        assert_eq!(name, "identity/x.json");
        assert_eq!(out, plaintext.as_bytes());
    }

    #[test]
    fn undecryptable_whole_file_blob_is_kept_verbatim_under_enc_name() {
        // Policy B: no key / bad envelope -> keep the file verbatim, never abort.
        let input = b"ENC[v1:not-decryptable]";
        let (name, out) = backup_entry_for_file("identity/x.json.enc", input, None);
        assert_eq!(name, "identity/x.json.enc");
        assert_eq!(out, input.to_vec());
    }

    #[test]
    fn plain_json_file_passes_through_field_normalization() {
        use crate::encryption::{EncryptionService, KeySource};

        let service = EncryptionService::new(KeySource::Raw { key: [3u8; 32] }).unwrap();
        let field = service
            .encrypt_field("hunter2")
            .unwrap();
        let input = format!(r#"{{"secret":"{field}"}}"#);

        let (name, out) = backup_entry_for_file("secrets/s.json", input.as_bytes(), Some(&service));
        assert_eq!(name, "secrets/s.json");
        let parsed: Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(parsed["secret"], Value::String("hunter2".to_string()));
    }

    #[test]
    fn non_json_file_entry_is_byte_identical() {
        let input = b"-----BEGIN CERTIFICATE-----\nabc\n-----END CERTIFICATE-----";
        let (name, out) = backup_entry_for_file("certs/leaf.pem", input, None);
        assert_eq!(name, "certs/leaf.pem");
        assert_eq!(out, input.to_vec());
    }
}
