//! Hybrid public-key encryption for storage exports.
//!
//! Scheme: Ed25519 public key → X25519 (via birational map) → ephemeral ECDH →
//! HKDF-SHA256 key derivation → AES-256-GCM authenticated encryption.
//!
//! Binary format (ATGX v1):
//! ```text
//! [4 bytes: magic "ATGX"]
//! [2 bytes: version 0x0001 big-endian]
//! [32 bytes: ephemeral X25519 public key]
//! [12 bytes: AES-GCM nonce]
//! [N bytes: ciphertext]
//! [16 bytes: AES-GCM auth tag]
//! ```

use anyhow::{Context, Result, bail};
use curve25519_dalek::edwards::CompressedEdwardsY;
use hkdf::Hkdf;
use ring::aead::{AES_256_GCM, Aad, BoundKey, Nonce, NonceSequence, OpeningKey, SealingKey, UnboundKey};
use ring::error::Unspecified;
use ring::rand::{SecureRandom, SystemRandom};
use sha2::Sha256;
use std::io::{self, BufRead};
use x25519_dalek::{PublicKey as X25519Public, StaticSecret as X25519Secret};

const MAGIC: &[u8; 4] = b"ATGX";
const VERSION: [u8; 2] = [0x00, 0x01];
const NONCE_LEN: usize = 12;
const HKDF_INFO: &[u8] = b"atg-export-v1";

/// Single-use nonce for ring's NonceSequence trait.
struct OneNonce(Option<Nonce>);

impl OneNonce {
    fn new(nonce: Nonce) -> Self {
        Self(Some(nonce))
    }
}

impl NonceSequence for OneNonce {
    fn advance(&mut self) -> Result<Nonce, Unspecified> {
        self.0
            .take()
            .ok_or(Unspecified)
    }
}

/// Read an Ed25519 public key from stdin (PEM-encoded).
/// Prompts the user and reads until a blank line or EOF.
pub fn read_ed25519_pubkey_interactive() -> Result<[u8; 32]> {
    eprintln!("Paste Ed25519 public key (PEM format), then press Enter on an empty line:");
    eprintln!();

    let stdin = io::stdin();
    let mut pem_text = String::new();
    for line in stdin.lock().lines() {
        let line = line.context("Failed to read stdin")?;
        if line.trim().is_empty() && pem_text.contains("-----END") {
            break;
        }
        pem_text.push_str(&line);
        pem_text.push('\n');
    }

    parse_ed25519_pubkey_pem(&pem_text)
}

/// Read an Ed25519 private key from stdin (PEM-encoded).
pub fn read_ed25519_privkey_interactive() -> Result<[u8; 32]> {
    eprintln!("Paste Ed25519 private key (PEM format), then press Enter on an empty line:");
    eprintln!();

    let stdin = io::stdin();
    let mut pem_text = String::new();
    for line in stdin.lock().lines() {
        let line = line.context("Failed to read stdin")?;
        if line.trim().is_empty() && pem_text.contains("-----END") {
            break;
        }
        pem_text.push_str(&line);
        pem_text.push('\n');
    }

    parse_ed25519_privkey_pem(&pem_text)
}

/// Parse a PEM-encoded Ed25519 public key and return the 32-byte key.
///
/// Accepts both raw 32-byte keys and PKCS#8/SubjectPublicKeyInfo wrapped keys
/// (the latter has a 12-byte ASN.1 prefix before the 32-byte key).
pub fn parse_ed25519_pubkey_pem(pem_text: &str) -> Result<[u8; 32]> {
    let parsed = pem::parse(pem_text).context("Invalid PEM format")?;
    let data = parsed.contents();

    match data.len() {
        32 => {
            let mut key = [0u8; 32];
            key.copy_from_slice(data);
            Ok(key)
        }
        44 => {
            // SubjectPublicKeyInfo wrapper: 12-byte ASN.1 header + 32-byte key
            // OID 1.3.101.112 (Ed25519)
            let mut key = [0u8; 32];
            key.copy_from_slice(&data[12..44]);
            Ok(key)
        }
        _ => bail!("Unexpected Ed25519 public key length: {} bytes (expected 32 or 44)", data.len()),
    }
}

/// Parse a PEM-encoded Ed25519 private key and return the 32-byte seed.
///
/// Accepts PKCS#8 wrapped keys (48 bytes: 16-byte ASN.1 header + 32-byte seed)
/// and raw 32-byte or 64-byte (seed+pubkey) formats.
fn parse_ed25519_privkey_pem(pem_text: &str) -> Result<[u8; 32]> {
    let parsed = pem::parse(pem_text).context("Invalid PEM format")?;
    let data = parsed.contents();

    match data.len() {
        32 => {
            let mut key = [0u8; 32];
            key.copy_from_slice(data);
            Ok(key)
        }
        48 => {
            // PKCS#8 wrapper: 16-byte ASN.1 header + 32-byte seed
            let mut key = [0u8; 32];
            key.copy_from_slice(&data[16..48]);
            Ok(key)
        }
        64 => {
            // Raw seed (32) + public key (32)
            let mut key = [0u8; 32];
            key.copy_from_slice(&data[..32]);
            Ok(key)
        }
        _ => bail!("Unexpected Ed25519 private key length: {} bytes (expected 32, 48, or 64)", data.len()),
    }
}

/// Convert an Ed25519 public key (Edwards point) to an X25519 public key (Montgomery point).
fn ed25519_pub_to_x25519(ed25519_pub: &[u8; 32]) -> Result<X25519Public> {
    let compressed = CompressedEdwardsY(*ed25519_pub);
    let edwards = compressed
        .decompress()
        .context("Invalid Ed25519 public key: cannot decompress Edwards point")?;
    let montgomery = edwards.to_montgomery();
    Ok(X25519Public::from(montgomery.to_bytes()))
}

/// Convert an Ed25519 private key seed to an X25519 secret key.
///
/// Ed25519 signing keys are derived from a seed via SHA-512; the lower 32 bytes
/// (with clamping) form the scalar, which is the same clamping X25519 applies.
fn ed25519_priv_to_x25519(ed25519_seed: &[u8; 32]) -> X25519Secret {
    use sha2::{Digest, Sha512};
    let hash = Sha512::digest(ed25519_seed);
    let mut scalar = [0u8; 32];
    scalar.copy_from_slice(&hash[..32]);
    // Clamping (same as X25519 does internally, but be explicit)
    scalar[0] &= 248;
    scalar[31] &= 127;
    scalar[31] |= 64;
    X25519Secret::from(scalar)
}

/// Derive a 32-byte AES key from a shared secret using HKDF-SHA256.
fn derive_aes_key(
    shared_secret: &[u8],
    ephemeral_pub: &[u8; 32],
) -> Result<[u8; 32]> {
    let hkdf = Hkdf::<Sha256>::new(Some(ephemeral_pub), shared_secret);
    let mut aes_key = [0u8; 32];
    hkdf.expand(HKDF_INFO, &mut aes_key)
        .map_err(|_| anyhow::anyhow!("HKDF expand failed"))?;
    Ok(aes_key)
}

/// Encrypt data with a recipient's Ed25519 public key.
///
/// Returns the full ATGX binary (header + ephemeral pubkey + nonce + ciphertext + tag).
pub fn encrypt_for_recipient(
    data: &[u8],
    ed25519_pub: &[u8; 32],
) -> Result<Vec<u8>> {
    let rng = SystemRandom::new();

    // Convert Ed25519 public key → X25519
    let recipient_x25519 = ed25519_pub_to_x25519(ed25519_pub)?;

    // Generate ephemeral X25519 keypair
    let mut ephemeral_secret_bytes = [0u8; 32];
    rng.fill(&mut ephemeral_secret_bytes)
        .map_err(|_| anyhow::anyhow!("Failed to generate random bytes"))?;
    let ephemeral_secret = X25519Secret::from(ephemeral_secret_bytes);
    let ephemeral_public = X25519Public::from(&ephemeral_secret);

    // ECDH
    let shared_secret = ephemeral_secret.diffie_hellman(&recipient_x25519);

    // Derive AES key
    let aes_key = derive_aes_key(shared_secret.as_bytes(), ephemeral_public.as_bytes())?;

    // Generate nonce
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rng.fill(&mut nonce_bytes)
        .map_err(|_| anyhow::anyhow!("Failed to generate nonce"))?;

    // AES-256-GCM encrypt
    let nonce = Nonce::assume_unique_for_key(nonce_bytes);
    let unbound_key =
        UnboundKey::new(&AES_256_GCM, &aes_key).map_err(|e| anyhow::anyhow!("Failed to create AES key: {:?}", e))?;
    let mut sealing_key = SealingKey::new(unbound_key, OneNonce::new(nonce));

    let mut ciphertext = data.to_vec();
    let tag = sealing_key
        .seal_in_place_separate_tag(Aad::empty(), &mut ciphertext)
        .map_err(|e| anyhow::anyhow!("AES-GCM seal failed: {:?}", e))?;
    ciphertext.extend_from_slice(tag.as_ref());

    // Build output: magic + version + ephemeral_pub + nonce + ciphertext+tag
    let mut output = Vec::with_capacity(4 + 2 + 32 + NONCE_LEN + ciphertext.len());
    output.extend_from_slice(MAGIC);
    output.extend_from_slice(&VERSION);
    output.extend_from_slice(ephemeral_public.as_bytes());
    output.extend_from_slice(&nonce_bytes);
    output.extend_from_slice(&ciphertext);

    Ok(output)
}

/// Decrypt an ATGX file with the recipient's Ed25519 private key seed.
///
/// Returns the decrypted plaintext (the ZIP archive).
pub fn decrypt_with_privkey(
    encrypted: &[u8],
    ed25519_seed: &[u8; 32],
) -> Result<Vec<u8>> {
    let header_len = 4 + 2 + 32 + NONCE_LEN; // magic + version + pubkey + nonce
    if encrypted.len() < header_len + AES_256_GCM.tag_len() {
        bail!("File too short to be a valid ATGX export");
    }

    // Verify magic
    if &encrypted[..4] != MAGIC {
        bail!("Not an ATGX export file (invalid magic bytes)");
    }

    // Verify version
    if encrypted[4..6] != VERSION {
        bail!("Unsupported ATGX version: {:02x}{:02x}", encrypted[4], encrypted[5]);
    }

    // Extract ephemeral public key
    let mut ephemeral_pub_bytes = [0u8; 32];
    ephemeral_pub_bytes.copy_from_slice(&encrypted[6..38]);
    let ephemeral_public = X25519Public::from(ephemeral_pub_bytes);

    // Extract nonce
    let nonce_bytes: [u8; NONCE_LEN] = encrypted[38..38 + NONCE_LEN]
        .try_into()
        .context("Failed to extract nonce")?;

    // Extract ciphertext + tag
    let ciphertext_and_tag = &encrypted[header_len..];

    // Convert Ed25519 seed → X25519 secret
    let x25519_secret = ed25519_priv_to_x25519(ed25519_seed);

    // ECDH
    let shared_secret = x25519_secret.diffie_hellman(&ephemeral_public);

    // Derive AES key
    let aes_key = derive_aes_key(shared_secret.as_bytes(), &ephemeral_pub_bytes)?;

    // AES-256-GCM decrypt
    let nonce = Nonce::assume_unique_for_key(nonce_bytes);
    let unbound_key =
        UnboundKey::new(&AES_256_GCM, &aes_key).map_err(|e| anyhow::anyhow!("Failed to create AES key: {:?}", e))?;
    let mut opening_key = OpeningKey::new(unbound_key, OneNonce::new(nonce));

    let mut in_out = ciphertext_and_tag.to_vec();
    let plaintext = opening_key
        .open_in_place(Aad::empty(), &mut in_out)
        .map_err(|_| anyhow::anyhow!("Decryption failed — wrong key or corrupted file"))?;

    Ok(plaintext.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_ed25519_keypair() -> ([u8; 32], [u8; 32]) {
        // Generate a deterministic test keypair from a seed
        use ed25519_dalek::SigningKey;
        let seed: [u8; 32] = [42u8; 32];
        let signing = SigningKey::from_bytes(&seed);
        let verifying = signing.verifying_key();
        (seed, verifying.to_bytes())
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let (seed, pubkey) = test_ed25519_keypair();
        let plaintext = b"Hello, this is a secret export!";

        let encrypted = encrypt_for_recipient(plaintext, &pubkey).unwrap();
        assert!(encrypted.starts_with(MAGIC));
        assert!(encrypted.len() > plaintext.len());

        let decrypted = decrypt_with_privkey(&encrypted, &seed).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_decrypt_large_data() {
        let (seed, pubkey) = test_ed25519_keypair();
        let plaintext: Vec<u8> = (0..10000)
            .map(|i| (i % 256) as u8)
            .collect();

        let encrypted = encrypt_for_recipient(&plaintext, &pubkey).unwrap();
        let decrypted = decrypt_with_privkey(&encrypted, &seed).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_wrong_key_fails() {
        let (_seed, pubkey) = test_ed25519_keypair();
        let wrong_seed = [99u8; 32];
        let plaintext = b"secret data";

        let encrypted = encrypt_for_recipient(plaintext, &pubkey).unwrap();
        let result = decrypt_with_privkey(&encrypted, &wrong_seed);
        assert!(result.is_err());
    }

    #[test]
    fn test_corrupted_data_fails() {
        let (seed, pubkey) = test_ed25519_keypair();
        let plaintext = b"secret data";

        let mut encrypted = encrypt_for_recipient(plaintext, &pubkey).unwrap();
        // Corrupt a byte in the ciphertext region
        let last = encrypted.len() - 5;
        encrypted[last] ^= 0xFF;

        let result = decrypt_with_privkey(&encrypted, &seed);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_magic_fails() {
        let seed = [42u8; 32];
        let data = b"NOT_ATGX_filexxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
        let result = decrypt_with_privkey(data, &seed);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("invalid magic")
        );
    }

    #[test]
    fn test_too_short_fails() {
        let seed = [42u8; 32];
        let result = decrypt_with_privkey(b"ATGX", &seed);
        assert!(result.is_err());
    }

    #[test]
    fn test_atgx_header_format() {
        let (_seed, pubkey) = test_ed25519_keypair();
        let encrypted = encrypt_for_recipient(b"test", &pubkey).unwrap();

        assert_eq!(&encrypted[..4], b"ATGX");
        assert_eq!(&encrypted[4..6], &[0x00, 0x01]);
        // ephemeral pubkey at [6..38], nonce at [38..50], ciphertext+tag after
        assert!(encrypted.len() >= 50 + 4 + 16); // header + "test" + tag
    }

    #[test]
    fn test_ed25519_pub_to_x25519_valid() {
        let (_seed, pubkey) = test_ed25519_keypair();
        let result = ed25519_pub_to_x25519(&pubkey);
        assert!(result.is_ok());
    }

    #[test]
    fn test_parse_ed25519_pubkey_pem_raw_32() {
        let key_bytes = [1u8; 32];
        let pem_obj = pem::Pem::new("PUBLIC KEY", key_bytes.to_vec());
        let pem_text = pem::encode(&pem_obj);
        let parsed = parse_ed25519_pubkey_pem(&pem_text).unwrap();
        assert_eq!(parsed, key_bytes);
    }

    #[test]
    fn test_parse_ed25519_privkey_pem_raw_32() {
        let key_bytes = [2u8; 32];
        let pem_obj = pem::Pem::new("PRIVATE KEY", key_bytes.to_vec());
        let pem_text = pem::encode(&pem_obj);
        let parsed = parse_ed25519_privkey_pem(&pem_text).unwrap();
        assert_eq!(parsed, key_bytes);
    }
}
