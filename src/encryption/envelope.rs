//! Envelope encryption implementation
//!
//! Envelope encryption is a key management pattern where:
//! 1. Data Encryption Keys (DEKs) are generated for encrypting data
//! 2. DEKs are encrypted with a Master Encryption Key (MEK)
//! 3. Encrypted DEKs are stored with the data
//! 4. DEKs are cached in memory for performance
//!
//! Benefits:
//! - Separate keys per data item/tenant for isolation
//! - Fast encryption/decryption (no MEK operations after DEK is cached)
//! - Easy key rotation (re-encrypt DEKs with new MEK)
//! - Scalable key management

use super::aes_gcm::AesGcmEncryptor;
use super::key_management::KeyManager;
use anyhow::{Context, Result, anyhow};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;
use std::sync::Arc;

/// Encrypted data with embedded DEK
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedData {
    /// Version of the encryption format
    pub version: u8,

    /// Data Encryption Key (DEK) encrypted with the Master Encryption Key (MEK)
    pub encrypted_dek: Vec<u8>,

    /// The actual encrypted data
    pub ciphertext: Vec<u8>,
}

impl EncryptedData {
    /// Convert to bytes for file storage
    #[allow(unused)]
    pub fn to_bytes(&self) -> Vec<u8> {
        // Simple format: [version: 1 byte][dek_len: 4 bytes][encrypted_dek][ciphertext]
        let mut bytes = Vec::new();
        bytes.push(self.version);
        bytes.extend_from_slice(&(self.encrypted_dek.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&self.encrypted_dek);
        bytes.extend_from_slice(&self.ciphertext);
        bytes
    }

    /// Parse from bytes
    #[allow(unused)]
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 5 {
            return Err(anyhow!("Invalid encrypted data: too short"));
        }

        let version = bytes[0];
        let dek_len = u32::from_le_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]) as usize;

        if bytes.len() < 5 + dek_len {
            return Err(anyhow!("Invalid encrypted data: invalid DEK length"));
        }

        let encrypted_dek = bytes[5..5 + dek_len].to_vec();
        let ciphertext = bytes[5 + dek_len..].to_vec();

        Ok(Self {
            version,
            encrypted_dek,
            ciphertext,
        })
    }
}

impl fmt::Display for EncryptedData {
    fn fmt(
        &self,
        f: &mut fmt::Formatter<'_>,
    ) -> fmt::Result {
        write!(f, "ENC[{}:{}:{}]", self.version, BASE64.encode(&self.encrypted_dek), BASE64.encode(&self.ciphertext))
    }
}

impl FromStr for EncryptedData {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        // Expected format: ENC[version:base64_dek:base64_ciphertext]
        if !s.starts_with("ENC[") || !s.ends_with(']') {
            return Err(anyhow!("Invalid encrypted data format"));
        }

        let content = &s[4..s.len() - 1];
        let parts: Vec<&str> = content.split(':').collect();

        if parts.len() != 3 {
            return Err(anyhow!("Invalid encrypted data format: expected 3 parts"));
        }

        let version = parts[0]
            .parse::<u8>()
            .context("Invalid version")?;

        let encrypted_dek = BASE64
            .decode(parts[1])
            .context("Failed to decode encrypted DEK")?;

        let ciphertext = BASE64
            .decode(parts[2])
            .context("Failed to decode ciphertext")?;

        Ok(Self {
            version,
            encrypted_dek,
            ciphertext,
        })
    }
}

/// Envelope encryption service with DEK caching
#[derive(Clone, Debug)]
pub struct EnvelopeEncryption {
    key_manager: Arc<KeyManager>,
    encryptor: AesGcmEncryptor,
    /// Cache of decrypted DEKs (in memory only)
    /// Key: base64(encrypted_dek), Value: [u8; 32] (decrypted DEK)
    dek_cache: DashMap<String, [u8; 32]>,
}

impl EnvelopeEncryption {
    /// Create a new envelope encryption service
    pub fn new(key_manager: KeyManager) -> Self {
        Self {
            key_manager: Arc::new(key_manager),
            encryptor: AesGcmEncryptor::new(),
            dek_cache: DashMap::new(),
        }
    }

    /// Encrypt data using envelope encryption
    ///
    /// Process:
    /// 1. Generate a new DEK
    /// 2. Encrypt the data with the DEK
    /// 3. Encrypt the DEK with the MEK
    /// 4. Return both encrypted DEK and ciphertext
    pub fn encrypt(
        &self,
        plaintext: &[u8],
    ) -> Result<EncryptedData> {
        // Generate a new DEK for this data
        let dek = self
            .key_manager
            .generate_dek()?;

        // Encrypt the data with the DEK
        let ciphertext = self
            .encryptor
            .encrypt(&dek, plaintext)
            .map_err(|e| anyhow!("Failed to encrypt data: {}", e))?;

        // Encrypt the DEK with the master key
        let encrypted_dek = self
            .key_manager
            .encrypt_dek(&dek)?;

        Ok(EncryptedData {
            version: 1,
            encrypted_dek,
            ciphertext,
        })
    }

    /// Decrypt data using envelope encryption
    ///
    /// Process:
    /// 1. Check DEK cache
    /// 2. If not cached, decrypt the DEK with the MEK and cache it
    /// 3. Decrypt the data with the DEK
    pub fn decrypt(
        &self,
        encrypted: &EncryptedData,
    ) -> Result<Vec<u8>> {
        // Check version
        if encrypted.version != 1 {
            return Err(anyhow!("Unsupported encryption version: {}", encrypted.version));
        }

        // Get the DEK (from cache or decrypt it)
        let dek = self.get_or_decrypt_dek(&encrypted.encrypted_dek)?;

        // Decrypt the data
        let plaintext = self
            .encryptor
            .decrypt(&dek, &encrypted.ciphertext)
            .map_err(|e| anyhow!("Failed to decrypt data: {}", e))?;

        Ok(plaintext)
    }

    /// Get a DEK from cache or decrypt it and cache it
    fn get_or_decrypt_dek(
        &self,
        encrypted_dek: &[u8],
    ) -> Result<[u8; 32]> {
        // Use base64-encoded DEK as cache key
        let cache_key = BASE64.encode(encrypted_dek);

        // Check cache first
        if let Some(cached_dek) = self.dek_cache.get(&cache_key) {
            return Ok(*cached_dek);
        }

        // Not in cache, decrypt it
        let dek = self
            .key_manager
            .decrypt_dek(encrypted_dek)?;

        // Cache it for next time
        self.dek_cache
            .insert(cache_key, dek);

        Ok(dek)
    }

    /// Clear the DEK cache (useful for key rotation)
    #[allow(unused)]
    pub fn clear_cache(&self) {
        self.dek_cache.clear();
    }

    /// Get cache statistics
    #[allow(unused)]
    pub fn cache_stats(&self) -> (usize, usize) {
        let len = self.dek_cache.len();
        let capacity = self.dek_cache.capacity();
        (len, capacity)
    }

    /// Encrypt with a specific DEK (advanced use case)
    pub fn encrypt_with_dek(
        &self,
        plaintext: &[u8],
        dek: &[u8; 32],
    ) -> Result<EncryptedData> {
        let ciphertext = self
            .encryptor
            .encrypt(dek, plaintext)
            .map_err(|e| anyhow!("Failed to encrypt data: {}", e))?;

        let encrypted_dek = self
            .key_manager
            .encrypt_dek(dek)?;

        Ok(EncryptedData {
            version: 1,
            encrypted_dek,
            ciphertext,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_envelope() -> EnvelopeEncryption {
        let key_manager = KeyManager::from_raw_key(&[42u8; 32]).unwrap();
        EnvelopeEncryption::new(key_manager)
    }

    #[test]
    fn test_encrypt_decrypt() {
        let envelope = create_test_envelope();
        let plaintext = b"Hello, envelope encryption!";

        let encrypted = envelope
            .encrypt(plaintext)
            .unwrap();
        let decrypted = envelope
            .decrypt(&encrypted)
            .unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypted_data_string_format() {
        let envelope = create_test_envelope();
        let plaintext = b"test data";

        let encrypted = envelope
            .encrypt(plaintext)
            .unwrap();
        let encrypted_str = encrypted.to_string();

        assert!(encrypted_str.starts_with("ENC["));
        assert!(encrypted_str.ends_with(']'));

        // Parse it back
        let parsed: EncryptedData = encrypted_str.parse().unwrap();
        let decrypted = envelope
            .decrypt(&parsed)
            .unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypted_data_bytes_format() {
        let envelope = create_test_envelope();
        let plaintext = b"test data";

        let encrypted = envelope
            .encrypt(plaintext)
            .unwrap();
        let bytes = encrypted.to_bytes();

        // Parse it back
        let parsed = EncryptedData::from_bytes(&bytes).unwrap();
        let decrypted = envelope
            .decrypt(&parsed)
            .unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_dek_caching() {
        let envelope = create_test_envelope();
        let plaintext = b"cached data";

        // First encryption/decryption
        let encrypted = envelope
            .encrypt(plaintext)
            .unwrap();
        let (cache_len_before, _) = envelope.cache_stats();

        // Decrypt (should cache the DEK)
        let _decrypted1 = envelope
            .decrypt(&encrypted)
            .unwrap();
        let (cache_len_after1, _) = envelope.cache_stats();

        assert!(cache_len_after1 > cache_len_before);

        // Decrypt again (should hit cache)
        let _decrypted2 = envelope
            .decrypt(&encrypted)
            .unwrap();
        let (cache_len_after2, _) = envelope.cache_stats();

        // Cache size should remain the same
        assert_eq!(cache_len_after1, cache_len_after2);
    }

    #[test]
    fn test_clear_cache() {
        let envelope = create_test_envelope();
        let plaintext = b"test";

        let encrypted = envelope
            .encrypt(plaintext)
            .unwrap();
        let _ = envelope
            .decrypt(&encrypted)
            .unwrap();

        let (cache_len, _) = envelope.cache_stats();
        assert!(cache_len > 0);

        envelope.clear_cache();

        let (cache_len_after, _) = envelope.cache_stats();
        assert_eq!(cache_len_after, 0);
    }

    #[test]
    fn test_different_deks_for_different_data() {
        let envelope = create_test_envelope();
        let plaintext1 = b"data1";
        let plaintext2 = b"data2";

        let encrypted1 = envelope
            .encrypt(plaintext1)
            .unwrap();
        let encrypted2 = envelope
            .encrypt(plaintext2)
            .unwrap();

        // Different DEKs should be generated
        assert_ne!(encrypted1.encrypted_dek, encrypted2.encrypted_dek);

        // But both should decrypt correctly
        let decrypted1 = envelope
            .decrypt(&encrypted1)
            .unwrap();
        let decrypted2 = envelope
            .decrypt(&encrypted2)
            .unwrap();

        assert_eq!(decrypted1, plaintext1);
        assert_eq!(decrypted2, plaintext2);
    }
}
