//! Development-only tracing backend (`key_source = local`).
//!
//! Performs **no encryption**. Every value is stored as a version-0 envelope
//! whose ciphertext is the plaintext itself, and every encrypt/decrypt call is
//! logged with the file it belongs to and the SHA-256 fingerprint of the bytes
//! on disk. The fingerprint is the same one the cached filesystem store uses to
//! decide whether a refresh has to decrypt a file again, so a local run with
//! periodic cache refresh enabled shows exactly which files a KMS-backed deployment would
//! send to `kms:Decrypt` on each refresh tick.

use super::envelope::EncryptedData;
use anyhow::{Result, anyhow};
use std::path::Path;
use tracing::info;

/// On-disk envelope version for the tracing backend. `0` marks a value that
/// was never encrypted; the real backends use `1` (local MEK) and `2` (KMS).
pub(crate) const LOCAL_TRACE_ENVELOPE_VERSION: u8 = 0;

/// Log target for the per-operation trace lines.
pub const LOCAL_TRACE_TARGET: &str = "encryption::local";

/// SHA-256 of `content`, used as the fingerprint of a stored file's bytes.
pub fn fingerprint(content: &[u8]) -> [u8; 32] {
    use sha2::Digest;
    sha2::Sha256::digest(content).into()
}

/// The pass-through cipher behind `key_source = local`.
#[derive(Clone, Copy, Default)]
pub(crate) struct LocalTrace;

impl LocalTrace {
    pub(crate) fn encrypt(
        &self,
        plaintext: &[u8],
    ) -> EncryptedData {
        EncryptedData {
            version: LOCAL_TRACE_ENVELOPE_VERSION,
            encrypted_dek: Vec::new(),
            ciphertext: plaintext.to_vec(),
        }
    }

    pub(crate) fn decrypt(
        &self,
        encrypted: &EncryptedData,
    ) -> Result<Vec<u8>> {
        if encrypted.version != LOCAL_TRACE_ENVELOPE_VERSION {
            return Err(anyhow!(
                "cannot decrypt a version-{} value: key_source is local (development, no encryption). \
                 Restore the key_source that wrote it to read it.",
                encrypted.version
            ));
        }
        Ok(encrypted.ciphertext.clone())
    }

    /// Log one completed operation. `stored` is the exact byte string that is
    /// (or was) on disk, so its fingerprint matches the storage layer's.
    pub(crate) fn record(
        &self,
        operation: &'static str,
        file: Option<&Path>,
        stored: &[u8],
    ) {
        let file = file
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "-".to_string());
        info!(
            target: LOCAL_TRACE_TARGET,
            "{operation} file={file} fingerprint={}",
            hex::encode(fingerprint(stored))
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_is_a_pass_through_with_version_zero() {
        let cipher = LocalTrace;
        let sealed = cipher.encrypt(b"{\"id\":\"a\"}");
        assert_eq!(sealed.version, 0);
        assert!(
            sealed
                .encrypted_dek
                .is_empty()
        );
        assert_eq!(
            cipher
                .decrypt(&sealed)
                .unwrap(),
            b"{\"id\":\"a\"}"
        );
        assert!(
            sealed
                .to_string()
                .starts_with("ENC[0::")
        );
    }

    #[test]
    fn refuses_envelopes_written_by_a_real_backend() {
        let cipher = LocalTrace;
        for version in [1u8, 2u8] {
            let foreign = EncryptedData {
                version,
                encrypted_dek: vec![1, 2, 3],
                ciphertext: vec![4, 5, 6],
            };
            let err = cipher
                .decrypt(&foreign)
                .unwrap_err()
                .to_string();
            assert!(err.contains(&format!("version-{version}")), "{err}");
            assert!(err.contains("local"), "{err}");
        }
    }

    #[test]
    fn fingerprint_is_sha256_of_the_bytes() {
        let fp = fingerprint(b"abc");
        assert_eq!(hex::encode(fp), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
        assert_ne!(fingerprint(b"abc"), fingerprint(b"abcd"));
    }
}
