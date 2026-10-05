// Reserved: crypto — encryption-at-rest primitives. Kept module-wide by design;
// dead-code sweeps must not touch this module without coordinating with the
// key-material-encryption effort. Crypto helpers are retained even
// when a given backend/path is not currently wired.
#![allow(dead_code)]
//! Encryption at rest module for securing sensitive data
//!
//! Provides AES-256-GCM envelope encryption for data stored on disk, with two
//! backends selected by `key_source` (see [`FieldCipher`]):
//! - **Local MEK** (`environment` / `file`): a Master Encryption Key is loaded at
//!   boot; per-value Data Encryption Keys (DEKs) are wrapped by the MEK and cached
//!   in memory. On-disk envelope `version = 1`.
//! - **AWS KMS** (`aws_kms`): no long-lived key in memory — a fresh data key is
//!   minted per value via `kms:GenerateDataKey` and recovered per read via
//!   `kms:Decrypt` (see [`kms_envelope`]). On-disk envelope `version = 2`; the
//!   plaintext key is zeroized after each op and every KMS error fails closed.
//! - **Local trace** (`local`, development only): no encryption at all. Values
//!   are stored as `version = 0` pass-through envelopes and every encrypt/decrypt
//!   is logged with its file name and fingerprint (see [`dev_trace`]).
//!
//! Key features:
//! - AES-256-GCM authenticated encryption
//! - Envelope encryption; version-byte dispatch between the two backends
//! - Whole-file encryption of stored JSON documents
//! - Backward compatibility with unencrypted (plaintext) data
//! - Boot preflight against cross-backend envelope mismatch (see [`preflight`])

pub(crate) mod aes_gcm;
mod data_key;
mod dev_trace;
mod envelope;
pub mod global;
pub mod init;
mod key_management;
mod kms_envelope;
pub mod migration;
pub mod preflight;
pub mod secret_file;

pub use dev_trace::{LOCAL_TRACE_TARGET, fingerprint};
pub use envelope::{EncryptedData, EnvelopeEncryption};
pub use key_management::{KeyManager, KeySource};

use self::dev_trace::LocalTrace;
use self::key_management::KmsDataKeys;
use self::kms_envelope::{KMS_ENVELOPE_VERSION, KmsEnvelope};
use anyhow::{Result, anyhow};
use std::path::Path;
use std::sync::Arc;

/// Field-encryption backend selected by `key_source`.
///
/// `LocalMek` writes/reads `version = 1` envelopes with a process-held MEK
/// (environment / file sources). `Kms` writes/reads `version = 2` per-value KMS
/// envelopes (`aws_kms`). `LocalTrace` (`local`) performs no encryption and
/// writes/reads `version = 0` pass-through envelopes, logging every operation.
/// Decrypt dispatches on the stored version byte and fails closed on a
/// cross-backend mismatch.
#[derive(Clone)]
enum FieldCipher {
    LocalMek(Arc<EnvelopeEncryption>),
    Kms(Arc<KmsEnvelope>),
    LocalTrace(LocalTrace),
}

impl std::fmt::Debug for FieldCipher {
    fn fmt(
        &self,
        f: &mut std::fmt::Formatter<'_>,
    ) -> std::fmt::Result {
        match self {
            FieldCipher::LocalMek(_) => f.write_str("FieldCipher::LocalMek"),
            FieldCipher::Kms(_) => f.write_str("FieldCipher::Kms"),
            FieldCipher::LocalTrace(_) => f.write_str("FieldCipher::LocalTrace"),
        }
    }
}

impl FieldCipher {
    fn encrypt(
        &self,
        plaintext: &[u8],
    ) -> Result<EncryptedData> {
        match self {
            FieldCipher::LocalMek(envelope) => envelope.encrypt(plaintext),
            FieldCipher::Kms(kms) => kms.encrypt(plaintext),
            FieldCipher::LocalTrace(trace) => Ok(trace.encrypt(plaintext)),
        }
    }

    fn decrypt(
        &self,
        encrypted: &EncryptedData,
    ) -> Result<Vec<u8>> {
        match self {
            FieldCipher::LocalMek(envelope) => {
                if encrypted.version == KMS_ENVELOPE_VERSION {
                    return Err(anyhow!(
                        "cannot decrypt a version-{KMS_ENVELOPE_VERSION} (AWS KMS) value: key_source is a \
                         local MEK (environment/file). Set key_source = \"aws_kms\" to read it."
                    ));
                }
                envelope.decrypt(encrypted)
            }
            FieldCipher::Kms(kms) => {
                if encrypted.version != KMS_ENVELOPE_VERSION {
                    return Err(anyhow!(
                        "cannot decrypt a version-{} (local MEK) value: key_source is aws_kms. Restore the \
                         original environment/file key_source to read it.",
                        encrypted.version
                    ));
                }
                kms.decrypt(encrypted)
            }
            FieldCipher::LocalTrace(trace) => trace.decrypt(encrypted),
        }
    }

    /// Log a completed whole-value operation when the tracing backend is active.
    fn record(
        &self,
        operation: &'static str,
        file: Option<&Path>,
        stored: &[u8],
    ) {
        if let FieldCipher::LocalTrace(trace) = self {
            trace.record(operation, file, stored);
        }
    }
}

/// Main encryption service that combines all encryption functionality
#[derive(Clone, Debug)]
pub struct EncryptionService {
    cipher: FieldCipher,
    enabled: bool,
}

impl EncryptionService {
    /// Create a new encryption service
    pub fn new(key_source: KeySource) -> Result<Self> {
        let key_manager = KeyManager::new(key_source)?;
        let envelope = EnvelopeEncryption::new(key_manager);

        Ok(Self {
            cipher: FieldCipher::LocalMek(Arc::new(envelope)),
            enabled: true,
        })
    }

    /// Create a disabled encryption service (pass-through mode)
    pub fn disabled() -> Self {
        // For disabled mode, we still need a minimal key manager
        // Use a dummy key that won't actually be used
        let key_manager =
            KeyManager::new(KeySource::Environment { var_name: "DUMMY".to_string() }).unwrap_or_else(|_| {
                // Fallback to a fixed key for disabled mode
                KeyManager::from_raw_key(&[0u8; 32]).unwrap()
            });
        let envelope = EnvelopeEncryption::new(key_manager);

        Self {
            cipher: FieldCipher::LocalMek(Arc::new(envelope)),
            enabled: false,
        }
    }

    /// Build a KMS-backed field-encryption service (`key_source = aws_kms`).
    ///
    /// Every value is protected with a per-value KMS envelope. Used by
    /// `init_encryption_service` for the real AWS client and by tests with a mock
    /// `KmsDataKeys`.
    pub(crate) fn with_kms(
        client: Arc<dyn KmsDataKeys>,
        key_id: String,
        max_concurrent_ops: usize,
    ) -> Self {
        let kms = KmsEnvelope::new(client, key_id, max_concurrent_ops);
        Self {
            cipher: FieldCipher::Kms(Arc::new(kms)),
            enabled: true,
        }
    }

    /// Build the development-only tracing backend (`key_source = local`).
    ///
    /// Performs no encryption: values are stored as pass-through envelopes and
    /// every whole-file operation is logged with its file name and fingerprint.
    pub fn local_trace() -> Self {
        Self {
            cipher: FieldCipher::LocalTrace(LocalTrace),
            enabled: true,
        }
    }

    /// Check if encryption is enabled
    #[allow(unused)]
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Encrypt a string value (for field-level encryption)
    pub fn encrypt_field(
        &self,
        value: &str,
    ) -> Result<String> {
        self.encrypt_value(None, value)
    }

    /// Decrypt a string value (for field-level encryption)
    pub fn decrypt_field(
        &self,
        encrypted: &str,
    ) -> Result<String> {
        self.decrypt_value(None, encrypted)
    }

    /// Encrypt the content of the storage file at `path` (whole-file encryption).
    ///
    /// Identical to [`Self::encrypt_string`] except that the tracing backend can
    /// name the file in its log line.
    pub fn encrypt_file(
        &self,
        path: &Path,
        plaintext: &str,
    ) -> Result<String> {
        self.encrypt_value(Some(path), plaintext)
    }

    /// Decrypt the content read from the storage file at `path`.
    ///
    /// Identical to [`Self::decrypt_string`] except that the tracing backend can
    /// name the file in its log line.
    pub fn decrypt_file(
        &self,
        path: &Path,
        ciphertext: &str,
    ) -> Result<String> {
        self.decrypt_value(Some(path), ciphertext)
    }

    fn encrypt_value(
        &self,
        file: Option<&Path>,
        value: &str,
    ) -> Result<String> {
        if !self.enabled {
            return Ok(value.to_string());
        }

        let encrypted = self
            .cipher
            .encrypt(value.as_bytes())?
            .to_string();
        self.cipher
            .record("encrypted", file, encrypted.as_bytes());
        Ok(encrypted)
    }

    fn decrypt_value(
        &self,
        file: Option<&Path>,
        encrypted: &str,
    ) -> Result<String> {
        if !self.enabled {
            return Ok(encrypted.to_string());
        }

        // Check if actually encrypted
        if !encrypted.starts_with("ENC[") {
            // Backward compatibility: return as-is if not encrypted
            return Ok(encrypted.to_string());
        }

        let encrypted_data: EncryptedData = encrypted.parse()?;
        let decrypted = self
            .cipher
            .decrypt(&encrypted_data)?;
        self.cipher
            .record("decrypted", file, encrypted.as_bytes());
        Ok(String::from_utf8(decrypted)?)
    }

    /// Encrypt bytes (for file-level encryption)
    #[allow(unused)]
    pub fn encrypt_bytes(
        &self,
        data: &[u8],
    ) -> Result<Vec<u8>> {
        if !self.enabled {
            return Ok(data.to_vec());
        }

        let encrypted = self.cipher.encrypt(data)?;
        Ok(encrypted.to_bytes())
    }

    /// Decrypt bytes (for file-level encryption)
    #[allow(unused)]
    pub fn decrypt_bytes(
        &self,
        data: &[u8],
    ) -> Result<Vec<u8>> {
        if !self.enabled {
            return Ok(data.to_vec());
        }

        let encrypted_data = EncryptedData::from_bytes(data)?;
        self.cipher
            .decrypt(&encrypted_data)
    }

    /// Encrypt a string (convenience method)
    pub fn encrypt_string(
        &self,
        plaintext: String,
    ) -> Result<String> {
        self.encrypt_field(&plaintext)
    }

    /// Decrypt a string (convenience method)
    pub fn decrypt_string(
        &self,
        ciphertext: String,
    ) -> Result<String> {
        self.decrypt_field(&ciphertext)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encryption_service_disabled() {
        let service = EncryptionService::disabled();
        assert!(!service.is_enabled());

        let plaintext = "hello world";
        let encrypted = service
            .encrypt_field(plaintext)
            .unwrap();
        assert_eq!(encrypted, plaintext);

        let decrypted = service
            .decrypt_field(&encrypted)
            .unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encryption_service_enabled() {
        // Use a fixed key for testing
        let key_manager = KeyManager::from_raw_key(&[42u8; 32]).unwrap();
        let envelope = EnvelopeEncryption::new(key_manager);
        let service = EncryptionService {
            cipher: FieldCipher::LocalMek(Arc::new(envelope)),
            enabled: true,
        };

        assert!(service.is_enabled());

        let plaintext = "secret data";
        let encrypted = service
            .encrypt_field(plaintext)
            .unwrap();
        assert_ne!(encrypted, plaintext);
        assert!(encrypted.starts_with("ENC["));

        let decrypted = service
            .decrypt_field(&encrypted)
            .unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_backward_compatibility() {
        let key_manager = KeyManager::from_raw_key(&[42u8; 32]).unwrap();
        let envelope = EnvelopeEncryption::new(key_manager);
        let service = EncryptionService {
            cipher: FieldCipher::LocalMek(Arc::new(envelope)),
            enabled: true,
        };

        // Should handle unencrypted data gracefully
        let plaintext = "not encrypted yet";
        let decrypted = service
            .decrypt_field(plaintext)
            .unwrap();
        assert_eq!(decrypted, plaintext);
    }

    use super::key_management::{GeneratedDataKey, KmsDataKeys as TestKmsDataKeys};

    struct IdentityKms;

    #[async_trait::async_trait]
    impl TestKmsDataKeys for IdentityKms {
        async fn generate_data_key(
            &self,
            _key_id: &str,
        ) -> Result<GeneratedDataKey> {
            // Distinct-enough key material for the test; identity-wrapped.
            let plaintext = vec![0x5Au8; 32];
            Ok(GeneratedDataKey {
                ciphertext_blob: plaintext.clone(),
                plaintext: zeroize::Zeroizing::new(plaintext),
            })
        }

        async fn decrypt(
            &self,
            _key_id: &str,
            ciphertext_blob: Vec<u8>,
        ) -> Result<zeroize::Zeroizing<Vec<u8>>> {
            Ok(zeroize::Zeroizing::new(ciphertext_blob))
        }
    }

    fn local_mek_service() -> EncryptionService {
        EncryptionService::new(KeySource::Raw { key: [7u8; 32] }).unwrap()
    }

    fn kms_service() -> EncryptionService {
        EncryptionService::with_kms(Arc::new(IdentityKms), "test-cmk".to_string(), 4)
    }

    #[test]
    fn kms_backend_round_trips_field() {
        let service = kms_service();
        let plaintext = "kms-protected-secret";
        let encrypted = service
            .encrypt_field(plaintext)
            .unwrap();
        assert!(encrypted.starts_with(&format!("ENC[{KMS_ENVELOPE_VERSION}:")));
        let decrypted = service
            .decrypt_field(&encrypted)
            .unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn local_mek_backend_rejects_kms_value() {
        // A value written under aws_kms (version 2) must fail closed under local MEK.
        let kms_value = kms_service()
            .encrypt_field("written-under-kms")
            .unwrap();
        let err = local_mek_service()
            .decrypt_field(&kms_value)
            .expect_err("local MEK must fail closed on a KMS envelope");
        assert!(
            err.to_string()
                .contains("aws_kms"),
            "error must name the required aws_kms backend, got: {err}"
        );
    }

    #[test]
    fn kms_backend_rejects_local_mek_value() {
        // A value written under local MEK (version 1) must fail closed under aws_kms.
        let local_value = local_mek_service()
            .encrypt_field("written-under-local")
            .unwrap();
        let err = kms_service()
            .decrypt_field(&local_value)
            .expect_err("aws_kms must fail closed on a local-MEK envelope");
        assert!(
            err.to_string()
                .contains("local MEK"),
            "error must name the local-MEK origin, got: {err}"
        );
    }

    #[test]
    fn local_trace_backend_round_trips_without_encrypting() {
        let service = EncryptionService::local_trace();
        assert!(service.is_enabled());
        let sealed = service
            .encrypt_field("visible-in-dev")
            .unwrap();
        assert!(sealed.starts_with("ENC[0::"), "{sealed}");
        assert_eq!(
            service
                .decrypt_field(&sealed)
                .unwrap(),
            "visible-in-dev"
        );
    }

    #[test]
    fn local_trace_backend_rejects_real_envelopes() {
        let service = EncryptionService::local_trace();
        for sealed in [
            local_mek_service()
                .encrypt_field("mek")
                .unwrap(),
            kms_service()
                .encrypt_field("kms")
                .unwrap(),
        ] {
            let err = service
                .decrypt_field(&sealed)
                .expect_err("local trace must fail closed on an encrypted envelope");
            assert!(
                err.to_string()
                    .contains("key_source is local"),
                "{err}"
            );
        }
    }

    /// Collects the message of every event logged under [`LOCAL_TRACE_TARGET`].
    fn capture_trace_lines<F: FnOnce()>(f: F) -> Vec<String> {
        use std::sync::Mutex;
        use tracing::field::{Field, Visit};
        use tracing_subscriber::layer::{Context, Layer, SubscriberExt};

        struct Lines(Arc<Mutex<Vec<String>>>);
        struct Message(Option<String>);

        impl Visit for Message {
            fn record_debug(
                &mut self,
                field: &Field,
                value: &dyn std::fmt::Debug,
            ) {
                if field.name() == "message" {
                    self.0 = Some(format!("{value:?}"));
                }
            }
        }

        impl<S: tracing::Subscriber> Layer<S> for Lines {
            fn on_event(
                &self,
                event: &tracing::Event<'_>,
                _ctx: Context<'_, S>,
            ) {
                if event.metadata().target() != LOCAL_TRACE_TARGET {
                    return;
                }
                let mut message = Message(None);
                event.record(&mut message);
                if let Some(line) = message.0 {
                    self.0
                        .lock()
                        .unwrap()
                        .push(line);
                }
            }
        }

        let lines = Arc::new(Mutex::new(Vec::new()));
        let subscriber = tracing_subscriber::registry().with(Lines(lines.clone()));
        tracing::subscriber::with_default(subscriber, f);
        lines.lock().unwrap().clone()
    }

    #[test]
    fn local_trace_logs_file_operations_with_the_on_disk_fingerprint() {
        let path = Path::new("/data/_storage/trust_registries/tr-1.json.enc");
        let mut sealed = String::new();
        let lines = capture_trace_lines(|| {
            let service = EncryptionService::local_trace();
            sealed = service
                .encrypt_file(path, "{\"id\":\"tr-1\"}")
                .unwrap();
            assert_eq!(
                service
                    .decrypt_file(path, &sealed)
                    .unwrap(),
                "{\"id\":\"tr-1\"}"
            );
            // Legacy plaintext is returned as-is and is not a decrypt operation.
            assert_eq!(
                service
                    .decrypt_file(path, "{\"legacy\":true}")
                    .unwrap(),
                "{\"legacy\":true}"
            );
        });

        let on_disk = hex::encode(fingerprint(sealed.as_bytes()));
        assert_eq!(
            lines,
            vec![
                format!("encrypted file={} fingerprint={on_disk}", path.display()),
                format!("decrypted file={} fingerprint={on_disk}", path.display()),
            ]
        );
    }

    #[test]
    fn local_trace_logs_field_operations_without_a_file() {
        let lines = capture_trace_lines(|| {
            let service = EncryptionService::local_trace();
            let sealed = service
                .encrypt_field("state")
                .unwrap();
            service
                .decrypt_field(&sealed)
                .unwrap();
        });
        assert_eq!(lines.len(), 2);
        assert!(lines[0].starts_with("encrypted file=- fingerprint="), "{}", lines[0]);
        assert!(lines[1].starts_with("decrypted file=- fingerprint="), "{}", lines[1]);
    }

    #[test]
    fn real_backends_log_nothing_under_the_trace_target() {
        let lines = capture_trace_lines(|| {
            let service = local_mek_service();
            let sealed = service
                .encrypt_file(Path::new("/x.json.enc"), "quiet")
                .unwrap();
            service
                .decrypt_file(Path::new("/x.json.enc"), &sealed)
                .unwrap();
        });
        assert!(lines.is_empty(), "{lines:?}");
    }
}
