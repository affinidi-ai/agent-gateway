//! Cryptographically secure key generation

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use rand::RngCore;
use uuid::Uuid;

/// Minimum key length in bytes (32 bytes = 256 bits)
pub const MIN_KEY_BYTES: usize = 32;

/// Key ID prefix for easy identification
pub const KEY_ID_PREFIX: &str = "atgk_";

/// Secret prefix for easy identification
pub const SECRET_PREFIX: &str = "atgs_";

/// Default key generator using CSPRNG
pub struct DefaultKeyGenerator;

impl DefaultKeyGenerator {
    /// Generate a new unique key ID
    pub fn generate_key_id() -> String {
        format!("{}{}", KEY_ID_PREFIX, Uuid::new_v4().as_simple())
    }

    /// Generate a cryptographically secure secret
    ///
    /// Uses the OS CSPRNG to generate random bytes, then base64-encodes them.
    /// The result is prefixed with `atgs_` for easy identification.
    pub fn generate_secret() -> String {
        let mut bytes = [0u8; MIN_KEY_BYTES];
        rand::rng().fill_bytes(&mut bytes);
        format!("{}{}", SECRET_PREFIX, URL_SAFE_NO_PAD.encode(bytes))
    }

    /// Generate both key_id and secret
    pub fn generate() -> (String, String) {
        (Self::generate_key_id(), Self::generate_secret())
    }
}

/// Hash an API key secret for storage and validation.
///
/// Returns the lowercase-hex SHA-256 of the secret. API key secrets are
/// 256-bit CSPRNG tokens, so a fast one-way hash is sufficient — brute-forcing
/// the pre-image is infeasible. The gateway persists only this hash and never
/// the raw secret; validation re-hashes the presented key and compares.
pub fn hash_secret(secret: &str) -> String {
    use sha2::{Digest, Sha256};

    let mut hasher = Sha256::new();
    hasher.update(secret.as_bytes());
    hex::encode(hasher.finalize())
}

/// Timing-safe comparison for secrets
///
/// This prevents timing attacks by ensuring comparison takes constant time.
pub fn constant_time_compare(
    a: &str,
    b: &str,
) -> bool {
    use subtle::ConstantTimeEq;

    if a.len() != b.len() {
        return false;
    }

    a.as_bytes()
        .ct_eq(b.as_bytes())
        .into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_key_id() {
        let key_id = DefaultKeyGenerator::generate_key_id();
        assert!(key_id.starts_with(KEY_ID_PREFIX));
        assert!(key_id.len() > KEY_ID_PREFIX.len());
    }

    #[test]
    fn test_generate_secret() {
        let secret = DefaultKeyGenerator::generate_secret();
        assert!(secret.starts_with(SECRET_PREFIX));
        // Base64 of 32 bytes = 43 chars + prefix
        assert!(secret.len() >= SECRET_PREFIX.len() + 40);
    }

    #[test]
    fn test_secrets_are_unique() {
        let s1 = DefaultKeyGenerator::generate_secret();
        let s2 = DefaultKeyGenerator::generate_secret();
        assert_ne!(s1, s2);
    }

    #[test]
    fn test_constant_time_compare() {
        assert!(constant_time_compare("hello", "hello"));
        assert!(!constant_time_compare("hello", "world"));
        assert!(!constant_time_compare("hello", "hello!"));
        assert!(!constant_time_compare("", "a"));
    }

    #[test]
    fn test_hash_secret_is_deterministic_and_hides_input() {
        let secret = DefaultKeyGenerator::generate_secret();
        let h1 = hash_secret(&secret);
        let h2 = hash_secret(&secret);
        assert_eq!(h1, h2, "hash must be deterministic");
        assert_eq!(h1.len(), 64, "SHA-256 hex is 64 chars");
        assert_ne!(h1, secret, "hash must not equal the raw secret");
    }

    #[test]
    fn test_hash_secret_differs_per_input() {
        let a = hash_secret("atgs_one");
        let b = hash_secret("atgs_two");
        assert_ne!(a, b);
    }
}
