//! AES-256-GCM authenticated encryption implementation using ring
//!
//! AES-GCM provides:
//! - Confidentiality (encryption)
//! - Authenticity (MAC)
//! - Integrity (tamper detection)
//!
//! This is a modern AEAD (Authenticated Encryption with Associated Data) cipher
//! that is both fast (hardware accelerated) and secure.

use anyhow::Result;
use ring::aead::{AES_256_GCM, Aad, BoundKey, Nonce, NonceSequence, OpeningKey, SealingKey, UnboundKey};
use ring::error::Unspecified;
use ring::rand::{SecureRandom, SystemRandom};
use std::num::NonZeroU32;
use thiserror::Error;

const NONCE_LEN: usize = 12; // 96 bits for GCM

#[derive(Error, Debug)]
pub enum EncryptionError {
    #[error("Failed to generate random nonce: {0}")]
    NonceGeneration(String),

    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),

    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),

    #[error("Invalid key length: expected 32 bytes, got {0}")]
    InvalidKeyLength(usize),

    #[error("Invalid ciphertext format")]
    InvalidFormat,
}

impl From<Unspecified> for EncryptionError {
    fn from(e: Unspecified) -> Self {
        EncryptionError::EncryptionFailed(format!("Ring error: {:?}", e))
    }
}

/// Single-use nonce generator
struct OneNonceSequence(Option<Nonce>);

impl OneNonceSequence {
    fn new(nonce: Nonce) -> Self {
        Self(Some(nonce))
    }
}

impl NonceSequence for OneNonceSequence {
    fn advance(&mut self) -> Result<Nonce, Unspecified> {
        self.0
            .take()
            .ok_or(Unspecified)
    }
}

/// AES-256-GCM encryptor
#[derive(Clone, Debug)]
pub struct AesGcmEncryptor {
    rng: SystemRandom,
}

impl AesGcmEncryptor {
    /// Create a new AES-GCM encryptor
    pub fn new() -> Self {
        Self { rng: SystemRandom::new() }
    }

    /// Generate a random 256-bit key
    pub fn generate_key(&self) -> Result<[u8; 32], EncryptionError> {
        let mut key = [0u8; 32];
        self.rng
            .fill(&mut key)
            .map_err(|e| EncryptionError::NonceGeneration(format!("{:?}", e)))?;
        Ok(key)
    }

    /// Encrypt plaintext with the given key
    ///
    /// Returns: nonce + ciphertext + tag (all concatenated)
    /// Format: [nonce: 12 bytes][ciphertext: N bytes][tag: 16 bytes]
    pub fn encrypt(
        &self,
        key: &[u8; 32],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, EncryptionError> {
        self.encrypt_with_aad(key, plaintext, &[])
    }

    pub fn encrypt_with_aad(
        &self,
        key: &[u8; 32],
        plaintext: &[u8],
        associated_data: &[u8],
    ) -> Result<Vec<u8>, EncryptionError> {
        // Validate key length
        if key.len() != 32 {
            return Err(EncryptionError::InvalidKeyLength(key.len()));
        }

        // Generate random nonce
        let mut nonce_bytes = [0u8; NONCE_LEN];
        self.rng
            .fill(&mut nonce_bytes)
            .map_err(|e| EncryptionError::NonceGeneration(format!("{:?}", e)))?;

        let nonce = Nonce::assume_unique_for_key(nonce_bytes);

        // Create sealing key
        let unbound_key = UnboundKey::new(&AES_256_GCM, key)
            .map_err(|e| EncryptionError::EncryptionFailed(format!("Failed to create key: {:?}", e)))?;

        let nonce_sequence = OneNonceSequence::new(nonce);
        let mut sealing_key = SealingKey::new(unbound_key, nonce_sequence);

        // Prepare output buffer: nonce + plaintext + tag overhead
        let mut in_out = Vec::with_capacity(NONCE_LEN + plaintext.len() + AES_256_GCM.tag_len());
        in_out.extend_from_slice(&nonce_bytes);
        in_out.extend_from_slice(plaintext);

        // Encrypt in place (starting after the nonce)
        let tag = sealing_key
            .seal_in_place_separate_tag(Aad::from(associated_data), &mut in_out[NONCE_LEN..])
            .map_err(|e| EncryptionError::EncryptionFailed(format!("Seal failed: {:?}", e)))?;

        // Append tag
        in_out.extend_from_slice(tag.as_ref());

        Ok(in_out)
    }

    /// Decrypt ciphertext with the given key
    ///
    /// Input format: [nonce: 12 bytes][ciphertext: N bytes][tag: 16 bytes]
    pub fn decrypt(
        &self,
        key: &[u8; 32],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, EncryptionError> {
        self.decrypt_with_aad(key, ciphertext, &[])
    }

    pub fn decrypt_with_aad(
        &self,
        key: &[u8; 32],
        ciphertext: &[u8],
        associated_data: &[u8],
    ) -> Result<Vec<u8>, EncryptionError> {
        // Validate key length
        if key.len() != 32 {
            return Err(EncryptionError::InvalidKeyLength(key.len()));
        }

        // Validate minimum length (nonce + tag)
        let min_len = NONCE_LEN + AES_256_GCM.tag_len();
        if ciphertext.len() < min_len {
            return Err(EncryptionError::InvalidFormat);
        }

        // Extract nonce
        let nonce_bytes: [u8; NONCE_LEN] = ciphertext[..NONCE_LEN]
            .try_into()
            .map_err(|_| EncryptionError::InvalidFormat)?;
        let nonce = Nonce::assume_unique_for_key(nonce_bytes);

        // Create opening key
        let unbound_key = UnboundKey::new(&AES_256_GCM, key)
            .map_err(|e| EncryptionError::DecryptionFailed(format!("Failed to create key: {:?}", e)))?;

        let nonce_sequence = OneNonceSequence::new(nonce);
        let mut opening_key = OpeningKey::new(unbound_key, nonce_sequence);

        // Decrypt in place
        let mut in_out = ciphertext[NONCE_LEN..].to_vec();
        let plaintext = opening_key
            .open_in_place(Aad::from(associated_data), &mut in_out)
            .map_err(|e| EncryptionError::DecryptionFailed(format!("Open failed: {:?}", e)))?;

        Ok(plaintext.to_vec())
    }

    /// Encrypt with PBKDF2 key derivation from password
    ///
    /// This is useful for password-based encryption but should not be used
    /// for high-performance scenarios. Use pre-generated keys instead.
    #[allow(unused)]
    pub fn encrypt_with_password(
        &self,
        password: &str,
        salt: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, EncryptionError> {
        let key = Self::derive_key_from_password(password, salt)?;
        self.encrypt(&key, plaintext)
    }

    /// Decrypt with PBKDF2 key derivation from password
    #[allow(unused)]
    pub fn decrypt_with_password(
        &self,
        password: &str,
        salt: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, EncryptionError> {
        let key = Self::derive_key_from_password(password, salt)?;
        self.decrypt(&key, ciphertext)
    }

    /// Derive a 256-bit key from password using PBKDF2
    #[allow(unused)]
    fn derive_key_from_password(
        password: &str,
        salt: &[u8],
    ) -> Result<[u8; 32], EncryptionError> {
        let iterations = NonZeroU32::new(100_000).unwrap(); // OWASP recommended minimum
        let mut key = [0u8; 32];

        ring::pbkdf2::derive(ring::pbkdf2::PBKDF2_HMAC_SHA256, iterations, salt, password.as_bytes(), &mut key);

        Ok(key)
    }
}

impl Default for AesGcmEncryptor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn associated_data_is_authenticated_without_changing_legacy_ciphertexts() {
        let encryptor = AesGcmEncryptor::new();
        let key = encryptor
            .generate_key()
            .unwrap();
        let ciphertext = encryptor
            .encrypt_with_aad(&key, b"private state", b"mcp:deployment:key-1")
            .unwrap();
        assert_eq!(
            encryptor
                .decrypt_with_aad(&key, &ciphertext, b"mcp:deployment:key-1")
                .unwrap(),
            b"private state"
        );
        assert!(
            encryptor
                .decrypt_with_aad(&key, &ciphertext, b"mcp:other:key-1")
                .is_err()
        );
        assert!(
            encryptor
                .decrypt(&key, &ciphertext)
                .is_err()
        );
        let legacy = encryptor
            .encrypt(&key, b"legacy")
            .unwrap();
        assert_eq!(
            encryptor
                .decrypt_with_aad(&key, &legacy, &[])
                .unwrap(),
            b"legacy"
        );
    }

    #[test]
    fn test_encrypt_decrypt() {
        let encryptor = AesGcmEncryptor::new();
        let key = encryptor
            .generate_key()
            .unwrap();
        let plaintext = b"Hello, World!";

        let ciphertext = encryptor
            .encrypt(&key, plaintext)
            .unwrap();
        assert_ne!(&ciphertext[NONCE_LEN..], plaintext);

        let decrypted = encryptor
            .decrypt(&key, &ciphertext)
            .unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_wrong_key_fails() {
        let encryptor = AesGcmEncryptor::new();
        let key1 = encryptor
            .generate_key()
            .unwrap();
        let key2 = encryptor
            .generate_key()
            .unwrap();
        let plaintext = b"secret data";

        let ciphertext = encryptor
            .encrypt(&key1, plaintext)
            .unwrap();

        // Decryption with wrong key should fail
        let result = encryptor.decrypt(&key2, &ciphertext);
        assert!(result.is_err());
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let encryptor = AesGcmEncryptor::new();
        let key = encryptor
            .generate_key()
            .unwrap();
        let plaintext = b"authentic data";

        let mut ciphertext = encryptor
            .encrypt(&key, plaintext)
            .unwrap();

        // Tamper with the ciphertext
        ciphertext[NONCE_LEN] ^= 0xFF;

        // Decryption should fail due to authentication tag mismatch
        let result = encryptor.decrypt(&key, &ciphertext);
        assert!(result.is_err());
    }

    #[test]
    fn test_password_based_encryption() {
        let encryptor = AesGcmEncryptor::new();
        let password = "my-secure-password";
        let salt = b"random-salt-value";
        let plaintext = b"password protected";

        let ciphertext = encryptor
            .encrypt_with_password(password, salt, plaintext)
            .unwrap();

        let decrypted = encryptor
            .decrypt_with_password(password, salt, &ciphertext)
            .unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_different_nonces() {
        let encryptor = AesGcmEncryptor::new();
        let key = encryptor
            .generate_key()
            .unwrap();
        let plaintext = b"same plaintext";

        let ciphertext1 = encryptor
            .encrypt(&key, plaintext)
            .unwrap();
        let ciphertext2 = encryptor
            .encrypt(&key, plaintext)
            .unwrap();

        // Different nonces should produce different ciphertexts
        assert_ne!(ciphertext1, ciphertext2);

        // But both should decrypt to the same plaintext
        let decrypted1 = encryptor
            .decrypt(&key, &ciphertext1)
            .unwrap();
        let decrypted2 = encryptor
            .decrypt(&key, &ciphertext2)
            .unwrap();

        assert_eq!(decrypted1, plaintext);
        assert_eq!(decrypted2, plaintext);
    }
}
