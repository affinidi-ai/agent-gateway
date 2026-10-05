//! Key management for encryption at rest
//!
//! This module handles:
//! - Loading the Master Encryption Key (MEK) from various sources
//! - Generating and caching Data Encryption Keys (DEKs)
//! - Key derivation and validation
//!
//! Key hierarchy:
//! - Master Encryption Key (MEK): Root key for encrypting DEKs
//! - Data Encryption Keys (DEKs): Per-tenant/store keys for encrypting data

use super::aes_gcm::AesGcmEncryptor;
use anyhow::{Context, Result, anyhow};
use async_trait::async_trait;
use aws_sdk_kms::Client as KmsClient;
use std::env;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use tracing::info;
use zeroize::Zeroizing;

/// Source for the master encryption key
#[derive(Debug, Clone)]
pub enum KeySource {
    /// Load key from environment variable
    Environment { var_name: String },

    /// Load key from file
    File { path: PathBuf },

    /// Use a raw key directly (for testing)
    #[allow(dead_code)]
    Raw { key: [u8; 32] },
}

/// A freshly minted AWS KMS data key: the 32-byte plaintext (wiped on drop) plus
/// its CMK-wrapped ciphertext, which is persisted alongside the value in the
/// on-disk envelope.
pub(crate) struct GeneratedDataKey {
    pub plaintext: Zeroizing<Vec<u8>>,
    pub ciphertext_blob: Vec<u8>,
}

/// KMS operations required by the per-value envelope backend.
///
/// A fresh data key is minted per encrypt (`generate_data_key`) and recovered
/// per read (`decrypt`); there is no cached key. Mockable in tests.
#[async_trait]
pub(crate) trait KmsDataKeys: Send + Sync {
    /// Mint a fresh AES-256 data key under `key_id` (`kms:GenerateDataKey`).
    async fn generate_data_key(
        &self,
        key_id: &str,
    ) -> Result<GeneratedDataKey>;

    /// Recover a CMK-wrapped data key (`kms:Decrypt`). The recovered plaintext is
    /// held in a zeroizing buffer so it is wiped on drop.
    async fn decrypt(
        &self,
        key_id: &str,
        ciphertext_blob: Vec<u8>,
    ) -> Result<Zeroizing<Vec<u8>>>;
}

struct AwsKmsDataKeysClient {
    client: KmsClient,
}

#[async_trait]
impl KmsDataKeys for AwsKmsDataKeysClient {
    async fn generate_data_key(
        &self,
        key_id: &str,
    ) -> Result<GeneratedDataKey> {
        let response = self
            .client
            .generate_data_key()
            .key_id(key_id)
            .key_spec(aws_sdk_kms::types::DataKeySpec::Aes256)
            .send()
            .await
            .context("AWS KMS GenerateDataKey request failed")?;

        // Extract the non-secret ciphertext blob first so a missing-field error can
        // never drop the plaintext key before it is wrapped in a zeroizing buffer.
        let ciphertext_blob = response
            .ciphertext_blob
            .context("AWS KMS GenerateDataKey response did not include ciphertext_blob")?
            .into_inner();
        let plaintext = Zeroizing::new(
            response
                .plaintext
                .context("AWS KMS GenerateDataKey response did not include plaintext")?
                .into_inner(),
        );

        Ok(GeneratedDataKey { plaintext, ciphertext_blob })
    }

    async fn decrypt(
        &self,
        key_id: &str,
        ciphertext_blob: Vec<u8>,
    ) -> Result<Zeroizing<Vec<u8>>> {
        let response = self
            .client
            .decrypt()
            .key_id(key_id)
            .ciphertext_blob(aws_sdk_kms::primitives::Blob::new(ciphertext_blob))
            .send()
            .await
            .context("AWS KMS decrypt request failed")?;

        let plaintext = response
            .plaintext
            .context("AWS KMS decrypt response did not include plaintext")?;

        Ok(Zeroizing::new(plaintext.into_inner()))
    }
}

/// Key manager responsible for loading and managing encryption keys
#[derive(Clone, Debug)]
pub struct KeyManager {
    master_key: [u8; 32],
    encryptor: AesGcmEncryptor,
}

impl KeyManager {
    /// Create a new key manager from a key source
    pub fn new(source: KeySource) -> Result<Self> {
        let master_key = Self::load_master_key(source)?;

        Ok(Self {
            master_key,
            encryptor: AesGcmEncryptor::new(),
        })
    }

    /// Create a key manager from a raw key (for testing)
    pub fn from_raw_key(key: &[u8; 32]) -> Result<Self> {
        Ok(Self {
            master_key: *key,
            encryptor: AesGcmEncryptor::new(),
        })
    }

    /// Load the master encryption key from the specified source
    fn load_master_key(source: KeySource) -> Result<[u8; 32]> {
        match source {
            KeySource::Environment { var_name } => {
                info!("Loading master encryption key from environment variable: {}", var_name);
                let key_str = env::var(&var_name).context(format!("Environment variable {} not found", var_name))?;

                Self::parse_key_string(&key_str)
            }

            KeySource::File { path } => {
                info!("Loading master encryption key from file: {}", path.display());
                let key_str =
                    fs::read_to_string(&path).context(format!("Failed to read key file: {}", path.display()))?;

                Self::parse_key_string(key_str.trim())
            }

            KeySource::Raw { key } => {
                info!("Using provided raw master encryption key");
                Ok(key)
            }
        }
    }

    fn create_kms_client_blocking() -> Result<AwsKmsDataKeysClient> {
        let sdk_config =
            Self::block_on(async { aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await })?;
        Ok(AwsKmsDataKeysClient {
            client: KmsClient::new(&sdk_config),
        })
    }

    /// Build the AWS KMS client used by the per-value envelope backend, as a
    /// trait object. Loads default AWS config (region/credentials) via the sync
    /// bridge; the CMK key id is supplied per operation by the caller.
    pub(crate) fn create_kms_data_keys_client() -> Result<Arc<dyn KmsDataKeys>> {
        Ok(Arc::new(Self::create_kms_client_blocking()?))
    }

    /// Run an async KMS future to completion from the synchronous serde/storage path.
    ///
    /// The production process runs on a **multi-thread** runtime (see `main.rs`, which builds
    /// `Builder::new_multi_thread()`), so the `MultiThread` arm — `block_in_place` — is the only
    /// path taken at runtime and boot. The `CurrentThread` arm is a fail-closed guard against
    /// misuse (e.g. a future `#[tokio::test]`, which defaults to a current-thread runtime, calling
    /// a real KMS path): `block_in_place` would panic there, so we return a clear error instead.
    /// The no-runtime branch builds a throwaway current-thread runtime for plain `#[test]` callers.
    pub(crate) fn block_on<F>(future: F) -> Result<F::Output>
    where
        F: std::future::Future,
    {
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            match handle.runtime_flavor() {
                tokio::runtime::RuntimeFlavor::MultiThread => {
                    Ok(tokio::task::block_in_place(|| handle.block_on(future)))
                }
                tokio::runtime::RuntimeFlavor::CurrentThread => {
                    Err(anyhow!("AWS KMS operations are not supported inside a current-thread Tokio runtime"))
                }
                _ => Err(anyhow!("Unsupported Tokio runtime flavor for AWS KMS operations")),
            }
        } else {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .context("Failed to create runtime for AWS KMS decrypt")?;
            Ok(runtime.block_on(future))
        }
    }

    /// Parse a key string (hex or base64)
    fn parse_key_string(s: &str) -> Result<[u8; 32]> {
        // Try hex first
        if s.len() == 64 {
            return Self::parse_hex_key(s);
        }

        // Try base64
        Self::parse_base64_key(s)
    }

    /// Parse a hex-encoded key
    fn parse_hex_key(s: &str) -> Result<[u8; 32]> {
        let bytes = hex::decode(s).context("Failed to decode hex key")?;

        if bytes.len() != 32 {
            return Err(anyhow!("Invalid key length: expected 32 bytes, got {}", bytes.len()));
        }

        let mut key = [0u8; 32];
        key.copy_from_slice(&bytes);
        Ok(key)
    }

    /// Parse a base64-encoded key
    fn parse_base64_key(s: &str) -> Result<[u8; 32]> {
        use base64::{Engine as _, engine::general_purpose::STANDARD};

        let bytes = STANDARD
            .decode(s)
            .context("Failed to decode base64 key")?;

        if bytes.len() != 32 {
            return Err(anyhow!("Invalid key length: expected 32 bytes, got {}", bytes.len()));
        }

        let mut key = [0u8; 32];
        key.copy_from_slice(&bytes);
        Ok(key)
    }

    /// Generate a new random master key
    #[allow(unused)]
    pub fn generate_master_key(&self) -> Result<[u8; 32]> {
        self.encryptor
            .generate_key()
            .map_err(|e| anyhow!("Failed to generate key: {}", e))
    }

    /// Generate a new data encryption key (DEK)
    #[allow(unused)]
    pub fn generate_dek(&self) -> Result<[u8; 32]> {
        self.encryptor
            .generate_key()
            .map_err(|e| anyhow!("Failed to generate DEK: {}", e))
    }

    /// Encrypt a DEK with the master key
    #[allow(unused)]
    pub fn encrypt_dek(
        &self,
        dek: &[u8; 32],
    ) -> Result<Vec<u8>> {
        self.encryptor
            .encrypt(&self.master_key, dek)
            .map_err(|e| anyhow!("Failed to encrypt DEK: {}", e))
    }

    /// Decrypt a DEK with the master key
    pub fn decrypt_dek(
        &self,
        encrypted_dek: &[u8],
    ) -> Result<[u8; 32]> {
        let decrypted = self
            .encryptor
            .decrypt(&self.master_key, encrypted_dek)
            .map_err(|e| anyhow!("Failed to decrypt DEK: {}", e))?;

        if decrypted.len() != 32 {
            return Err(anyhow!("Invalid DEK length: expected 32 bytes, got {}", decrypted.len()));
        }

        let mut dek = [0u8; 32];
        dek.copy_from_slice(&decrypted);
        Ok(dek)
    }

    /// Get the master key (use with caution)
    #[allow(unused)]
    pub fn master_key(&self) -> &[u8; 32] {
        &self.master_key
    }

    /// Get access to the encryptor
    #[allow(unused)]
    pub fn encryptor(&self) -> &AesGcmEncryptor {
        &self.encryptor
    }
}

/// Generate and print a new master key
#[allow(unused)]
pub fn generate_and_print_master_key() -> Result<()> {
    let encryptor = AesGcmEncryptor::new();
    let key = encryptor
        .generate_key()
        .map_err(|e| anyhow!("Failed to generate key: {}", e))?;

    use base64::{Engine as _, engine::general_purpose::STANDARD};

    println!("Generated Master Encryption Key:");
    println!();
    println!("Hex format (64 characters):");
    println!("{}", hex::encode(key));
    println!();
    println!("Base64 format:");
    println!("{}", STANDARD.encode(key));
    println!();
    println!("Set this in your environment:");
    println!("export AG_MASTER_KEY=\"{}\"", STANDARD.encode(key));

    Ok(())
}

// We need hex and base64 dependencies
// Add to Cargo.toml

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_key() {
        let manager = KeyManager::from_raw_key(&[42u8; 32]).unwrap();
        let dek = manager
            .generate_dek()
            .unwrap();
        assert_eq!(dek.len(), 32);
    }

    #[test]
    fn test_encrypt_decrypt_dek() {
        let manager = KeyManager::from_raw_key(&[42u8; 32]).unwrap();
        let dek = [1u8; 32];

        let encrypted = manager
            .encrypt_dek(&dek)
            .unwrap();
        let decrypted = manager
            .decrypt_dek(&encrypted)
            .unwrap();

        assert_eq!(decrypted, dek);
    }

    #[test]
    fn test_parse_hex_key() {
        let hex_sample = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let key = KeyManager::parse_hex_key(hex_sample).unwrap();
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn test_parse_base64_key() {
        use base64::{Engine as _, engine::general_purpose::STANDARD};
        let key_bytes = [42u8; 32];
        let base64_key = STANDARD.encode(key_bytes);
        let key = KeyManager::parse_base64_key(&base64_key).unwrap();
        assert_eq!(key, key_bytes);
    }

    #[test]
    fn test_from_raw_key() {
        let raw_key = [99u8; 32];
        let manager = KeyManager::from_raw_key(&raw_key).unwrap();
        assert_eq!(manager.master_key(), &raw_key);
    }

    // The API-key / secrets stores are constructed synchronously via
    // `block_in_place(|| Handle::block_on(cached_storage(...)))`. When per-value KMS is active on the
    // serde hot path, deserializing a stored record inside that outer bridge reaches the KMS decrypt
    // bridge (`KeyManager::block_on`), producing a nested
    // `block_in_place -> block_on -> block_in_place -> block_on` shape. This test proves that nesting
    // does not panic on a multi-thread runtime (the only flavor real serde sites run on), so the
    // existing guarded bridge is safe to reuse there without a dedicated KMS executor.
    #[test]
    fn test_nested_block_on_bridge_survives_store_construction_nesting() {
        struct NestTestKms {
            plaintext: Vec<u8>,
        }

        #[async_trait]
        impl KmsDataKeys for NestTestKms {
            async fn generate_data_key(
                &self,
                _key_id: &str,
            ) -> Result<GeneratedDataKey> {
                Ok(GeneratedDataKey {
                    ciphertext_blob: self.plaintext.clone(),
                    plaintext: Zeroizing::new(self.plaintext.clone()),
                })
            }

            async fn decrypt(
                &self,
                _key_id: &str,
                _ciphertext_blob: Vec<u8>,
            ) -> Result<Zeroizing<Vec<u8>>> {
                Ok(Zeroizing::new(self.plaintext.clone()))
            }
        }

        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();

        let expected = vec![7u8; 32];
        let client = NestTestKms { plaintext: expected.clone() };

        let recovered = runtime.block_on(async move {
            // Outer bridge: mirrors `FilesystemApiKeyStore::new` / `FilesystemSecretStore::new`.
            tokio::task::block_in_place(|| {
                tokio::runtime::Handle::current().block_on(async {
                    // Inner bridge: mirrors a serde-path field decrypt reaching KMS.
                    KeyManager::block_on(client.decrypt("kms-key", vec![1, 2, 3]))
                        .expect("guarded bridge must not error on a multi-thread runtime")
                        .expect("mock KMS decrypt must succeed")
                })
            })
        });

        assert_eq!(recovered.as_slice(), expected.as_slice());
    }

    // Companion guard: the guarded bridge must refuse (not panic) on a current-thread runtime.
    // Current-thread runtimes only appear in some test harnesses, never at the real serde sites.
    #[test]
    fn test_block_on_bridge_errors_on_current_thread_runtime() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        let result =
            runtime.block_on(async { KeyManager::block_on(async { Ok::<Vec<u8>, anyhow::Error>(vec![0u8; 32]) }) });

        let err = result.expect_err("current-thread runtime must be rejected, not silently blocked");
        assert!(
            err.to_string()
                .contains("current-thread"),
            "error must name the current-thread limitation, got: {err}"
        );
    }
}
