//! AWS KMS per-value envelope encryption backend.
//!
//! When `key_source = aws_kms`, every field-encrypted value is protected with a
//! fresh KMS-minted data key:
//!
//! - **encrypt:** `kms:GenerateDataKey` → a fresh 32-byte AES-256 key + its
//!   CMK-wrapped ciphertext. AES-256-GCM encrypts the value with the plaintext
//!   key; the wrapped key is stored as `EncryptedData.encrypted_dek` with
//!   `version = 2`. The plaintext key is zeroized immediately.
//! - **decrypt:** `kms:Decrypt` recovers the wrapped key, AES-256-GCM decrypts,
//!   then the key is zeroized.
//!
//! There is no cached data key and no long-lived MEK: every op is a KMS round
//! trip, and any KMS error fails closed. Concurrent KMS ops are bounded by a
//! semaphore. The sync serde path reaches these async ops through the existing
//! runtime-flavor-guarded [`KeyManager::block_on`] bridge.

use super::aes_gcm::AesGcmEncryptor;
use super::data_key::DataKey;
use super::envelope::EncryptedData;
use super::key_management::{KeyManager, KmsDataKeys};
use anyhow::{Result, anyhow};
use std::sync::Arc;
use tokio::sync::Semaphore;

/// On-disk envelope version for KMS per-value encryption.
///
/// `1` = legacy local-MEK envelope; `2` = `encrypted_dek` holds the KMS
/// `CiphertextBlob`.
pub(crate) const KMS_ENVELOPE_VERSION: u8 = 2;

/// Per-value KMS envelope encryption backend.
pub struct KmsEnvelope {
    client: Arc<dyn KmsDataKeys>,
    key_id: String,
    encryptor: AesGcmEncryptor,
    semaphore: Arc<Semaphore>,
}

impl KmsEnvelope {
    /// Build a KMS envelope backend bound to `key_id`, bounding concurrent KMS
    /// operations to `max_concurrent_ops` (a value of 0 is treated as 1).
    pub(crate) fn new(
        client: Arc<dyn KmsDataKeys>,
        key_id: String,
        max_concurrent_ops: usize,
    ) -> Self {
        let permits = max_concurrent_ops.max(1);
        Self {
            client,
            key_id,
            encryptor: AesGcmEncryptor::new(),
            semaphore: Arc::new(Semaphore::new(permits)),
        }
    }

    /// Encrypt `plaintext` with a fresh KMS-minted data key.
    ///
    /// Fails closed on any KMS error; the plaintext data key is zeroized on every
    /// path (including error) via [`DataKey`].
    pub(crate) fn encrypt(
        &self,
        plaintext: &[u8],
    ) -> Result<EncryptedData> {
        let started = std::time::Instant::now();
        let generated = KeyManager::block_on(async {
            let _permit = self
                .semaphore
                .acquire()
                .await
                .map_err(|_| anyhow!("KMS concurrency semaphore closed"))?;
            self.client
                .generate_data_key(&self.key_id)
                .await
        })
        .and_then(|inner| inner);
        record_kms_metric("generate_data_key", started, generated.is_ok());
        let generated = generated?;

        let data_key = DataKey::from_kms_plaintext(generated.plaintext)?;
        let ciphertext = self
            .encryptor
            .encrypt(data_key.as_bytes(), plaintext)
            .map_err(|e| anyhow!("AES-256-GCM encrypt failed: {e}"))?;

        Ok(EncryptedData {
            version: KMS_ENVELOPE_VERSION,
            encrypted_dek: generated.ciphertext_blob,
            ciphertext,
        })
    }

    /// Decrypt a `version = 2` KMS envelope value.
    ///
    /// Fails closed on a non-KMS version, on any KMS error, and on AES failure;
    /// the plaintext data key is zeroized on every path.
    pub(crate) fn decrypt(
        &self,
        encrypted: &EncryptedData,
    ) -> Result<Vec<u8>> {
        if encrypted.version != KMS_ENVELOPE_VERSION {
            return Err(anyhow!(
                "KMS envelope cannot decrypt version {} (expected {})",
                encrypted.version,
                KMS_ENVELOPE_VERSION
            ));
        }

        let wrapped = encrypted
            .encrypted_dek
            .clone();
        let started = std::time::Instant::now();
        let plaintext_key = KeyManager::block_on(async {
            let _permit = self
                .semaphore
                .acquire()
                .await
                .map_err(|_| anyhow!("KMS concurrency semaphore closed"))?;
            self.client
                .decrypt(&self.key_id, wrapped)
                .await
        })
        .and_then(|inner| inner);
        record_kms_metric("decrypt", started, plaintext_key.is_ok());
        let plaintext_key = plaintext_key?;

        let data_key = DataKey::from_kms_plaintext(plaintext_key)?;
        let plaintext = self
            .encryptor
            .decrypt(data_key.as_bytes(), &encrypted.ciphertext)
            .map_err(|e| anyhow!("AES-256-GCM decrypt failed: {e}"))?;

        Ok(plaintext)
    }
}

/// Emit the `kms_operation` metric (op, result) + latency for one KMS call.
fn record_kms_metric(
    op: &str,
    started: std::time::Instant,
    ok: bool,
) {
    let result = if ok {
        "ok"
    } else {
        "error"
    };
    crate::metrics::backends::prometheus::track_kms_operation(
        op,
        result,
        started
            .elapsed()
            .as_secs_f64(),
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encryption::key_management::GeneratedDataKey;
    use async_trait::async_trait;
    use std::sync::Mutex;

    enum MockMode {
        RoundTrip,
        FailGenerate,
        FailDecrypt,
    }

    /// Mock KMS: `generate_data_key` mints a distinct 32-byte key per call
    /// (counter-derived) and uses an identity wrap (`ciphertext_blob == plaintext`)
    /// so `decrypt` round-trips. Fail modes exercise the fail-closed contract.
    struct MockKms {
        mode: MockMode,
        calls: Mutex<u32>,
    }

    impl MockKms {
        fn new(mode: MockMode) -> Arc<Self> {
            Arc::new(Self { mode, calls: Mutex::new(0) })
        }
    }

    #[async_trait]
    impl KmsDataKeys for MockKms {
        async fn generate_data_key(
            &self,
            _key_id: &str,
        ) -> Result<GeneratedDataKey> {
            if matches!(self.mode, MockMode::FailGenerate) {
                return Err(anyhow!("mock GenerateDataKey failure"));
            }
            let n = {
                let mut c = self.calls.lock().unwrap();
                *c += 1;
                *c as u8
            };
            let mut plaintext = vec![0u8; 32];
            for (i, b) in plaintext
                .iter_mut()
                .enumerate()
            {
                *b = n.wrapping_add(i as u8);
            }
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
            if matches!(self.mode, MockMode::FailDecrypt) {
                return Err(anyhow!("mock Decrypt failure"));
            }
            Ok(zeroize::Zeroizing::new(ciphertext_blob))
        }
    }

    fn envelope(mode: MockMode) -> KmsEnvelope {
        KmsEnvelope::new(MockKms::new(mode), "test-cmk".to_string(), 4)
    }

    #[test]
    fn round_trips_utf8_value() {
        let env = envelope(MockMode::RoundTrip);
        let secret = b"super-secret-private-key-material";
        let encrypted = env.encrypt(secret).unwrap();
        assert_eq!(encrypted.version, KMS_ENVELOPE_VERSION);
        let decrypted = env
            .decrypt(&encrypted)
            .unwrap();
        assert_eq!(decrypted, secret);
    }

    #[test]
    fn round_trips_json_and_pem_shapes() {
        let env = envelope(MockMode::RoundTrip);
        for value in
            [br#"{"kty":"OKP","d":"abc"}"#.as_slice(), b"-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----"]
        {
            let encrypted = env.encrypt(value).unwrap();
            let decrypted = env
                .decrypt(&encrypted)
                .unwrap();
            assert_eq!(decrypted, value);
        }
    }

    #[test]
    fn distinct_encrypted_dek_per_encrypt() {
        let env = envelope(MockMode::RoundTrip);
        let value = b"same-plaintext";
        let first = env.encrypt(value).unwrap();
        let second = env.encrypt(value).unwrap();
        assert_ne!(first.encrypted_dek, second.encrypted_dek, "each encrypt must mint a fresh data key (no reuse)");
        // Both still round-trip independently.
        assert_eq!(env.decrypt(&first).unwrap(), value);
        assert_eq!(env.decrypt(&second).unwrap(), value);
    }

    #[test]
    fn fails_closed_on_generate_error() {
        let env = envelope(MockMode::FailGenerate);
        let err = env
            .encrypt(b"secret")
            .unwrap_err();
        assert!(
            err.to_string()
                .contains("GenerateDataKey"),
            "got: {err}"
        );
    }

    #[test]
    fn fails_closed_on_decrypt_error() {
        // Encrypt with a working backend, then decrypt with a failing one.
        let good = envelope(MockMode::RoundTrip);
        let encrypted = good
            .encrypt(b"secret")
            .unwrap();
        let bad = envelope(MockMode::FailDecrypt);
        let err = bad
            .decrypt(&encrypted)
            .unwrap_err();
        assert!(
            err.to_string()
                .contains("Decrypt"),
            "got: {err}"
        );
    }

    #[test]
    fn rejects_non_kms_version() {
        let env = envelope(MockMode::RoundTrip);
        let legacy = EncryptedData {
            version: 1,
            encrypted_dek: vec![0u8; 32],
            ciphertext: vec![0u8; 16],
        };
        let err = env
            .decrypt(&legacy)
            .unwrap_err();
        assert!(
            err.to_string()
                .contains("cannot decrypt version 1"),
            "got: {err}"
        );
    }

    #[test]
    fn emits_kms_metric_on_encrypt_and_decrypt() {
        use crate::metrics::backends::prometheus::KMS_OPERATION;
        let gen_ok_before = KMS_OPERATION
            .with_label_values(&["generate_data_key", "ok"])
            .get();
        let dec_ok_before = KMS_OPERATION
            .with_label_values(&["decrypt", "ok"])
            .get();

        let env = envelope(MockMode::RoundTrip);
        let encrypted = env
            .encrypt(b"metric-secret")
            .unwrap();
        let _ = env
            .decrypt(&encrypted)
            .unwrap();

        assert!(
            KMS_OPERATION
                .with_label_values(&["generate_data_key", "ok"])
                .get()
                > gen_ok_before,
            "generate_data_key ok counter must increment"
        );
        assert!(
            KMS_OPERATION
                .with_label_values(&["decrypt", "ok"])
                .get()
                > dec_ok_before,
            "decrypt ok counter must increment"
        );
    }

    #[test]
    fn emits_error_metric_on_kms_failure() {
        use crate::metrics::backends::prometheus::KMS_OPERATION;
        let before = KMS_OPERATION
            .with_label_values(&["generate_data_key", "error"])
            .get();

        let env = envelope(MockMode::FailGenerate);
        let _ = env
            .encrypt(b"secret")
            .unwrap_err();

        assert!(
            KMS_OPERATION
                .with_label_values(&["generate_data_key", "error"])
                .get()
                > before,
            "generate_data_key error counter must increment on KMS failure"
        );
    }

    #[test]
    fn bounds_concurrent_kms_ops_to_cap() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        struct ConcurrencyMock {
            in_flight: AtomicUsize,
            max_seen: AtomicUsize,
        }

        #[async_trait]
        impl KmsDataKeys for ConcurrencyMock {
            async fn generate_data_key(
                &self,
                _key_id: &str,
            ) -> Result<GeneratedDataKey> {
                let now = self
                    .in_flight
                    .fetch_add(1, Ordering::SeqCst)
                    + 1;
                self.max_seen
                    .fetch_max(now, Ordering::SeqCst);
                tokio::time::sleep(std::time::Duration::from_millis(25)).await;
                self.in_flight
                    .fetch_sub(1, Ordering::SeqCst);
                let pt = vec![1u8; 32];
                Ok(GeneratedDataKey {
                    ciphertext_blob: pt.clone(),
                    plaintext: zeroize::Zeroizing::new(pt),
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

        let cap = 3usize;
        let mock = Arc::new(ConcurrencyMock {
            in_flight: AtomicUsize::new(0),
            max_seen: AtomicUsize::new(0),
        });
        let env = Arc::new(KmsEnvelope::new(mock.clone(), "cmk".to_string(), cap));

        let mut handles = Vec::new();
        for _ in 0..12 {
            let env = env.clone();
            handles.push(std::thread::spawn(move || {
                env.encrypt(b"x").unwrap();
            }));
        }
        for h in handles {
            h.join().unwrap();
        }

        let max = mock
            .max_seen
            .load(Ordering::SeqCst);
        assert!(max >= 2, "the semaphore must allow real concurrency, not pin ops to 1 (max_seen={max})");
        assert!(max <= cap, "in-flight KMS ops ({max}) must never exceed the cap ({cap})");
    }

    #[test]
    fn cap_zero_does_not_hang() {
        // `kms_max_concurrent_ops = 0` is operator-settable; the `.max(1)` guard in `new` prevents a
        // `Semaphore::new(0)` + `acquire().await` deadlock (a silent boot hang). Run in a thread with
        // a join timeout so a regression fails as a timeout instead of hanging the whole test run.
        use std::sync::mpsc;
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let env = KmsEnvelope::new(MockKms::new(MockMode::RoundTrip), "cmk".to_string(), 0);
            let _ = tx.send(env.encrypt(b"x").is_ok());
        });
        match rx.recv_timeout(std::time::Duration::from_secs(5)) {
            Ok(ok) => assert!(ok, "encrypt with kms_max_concurrent_ops=0 must succeed via the max(1) guard"),
            Err(_) => panic!("KmsEnvelope with kms_max_concurrent_ops=0 hung — the max(1) guard is missing"),
        }
    }

    #[test]
    fn tampered_ciphertext_fails_closed() {
        // Proves the KMS path authenticates the payload (AES-256-GCM), not merely recovers the DEK.
        let env = envelope(MockMode::RoundTrip);
        let mut encrypted = env
            .encrypt(b"authentic-private-key-material")
            .unwrap();
        // Flip the first AES-GCM ciphertext byte (index 0..12 is the nonce).
        encrypted.ciphertext[12] ^= 0xFF;
        let err = env
            .decrypt(&encrypted)
            .unwrap_err();
        assert!(
            err.to_string()
                .contains("AES-256-GCM decrypt failed"),
            "tampered ciphertext must fail the AEAD auth, got: {err}"
        );
    }

    #[test]
    fn decrypt_wrong_length_key_fails_closed() {
        // A KMS `Decrypt` that returns a non-32-byte plaintext must fail closed at the envelope seam,
        // never AES-decrypting with a short key.
        struct WrongLenKms;

        #[async_trait]
        impl KmsDataKeys for WrongLenKms {
            async fn generate_data_key(
                &self,
                _key_id: &str,
            ) -> Result<GeneratedDataKey> {
                let pt = vec![0u8; 32];
                Ok(GeneratedDataKey {
                    ciphertext_blob: pt.clone(),
                    plaintext: zeroize::Zeroizing::new(pt),
                })
            }

            async fn decrypt(
                &self,
                _key_id: &str,
                _ciphertext_blob: Vec<u8>,
            ) -> Result<zeroize::Zeroizing<Vec<u8>>> {
                Ok(zeroize::Zeroizing::new(vec![0u8; 16]))
            }
        }

        let env = KmsEnvelope::new(Arc::new(WrongLenKms), "cmk".to_string(), 4);
        let value = EncryptedData {
            version: KMS_ENVELOPE_VERSION,
            encrypted_dek: vec![0u8; 10],
            ciphertext: vec![0u8; 30],
        };
        let err = env
            .decrypt(&value)
            .unwrap_err();
        assert!(
            err.to_string()
                .contains("expected 32 bytes"),
            "a wrong-length KMS plaintext key must fail closed, got: {err}"
        );
    }
}
