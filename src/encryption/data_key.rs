//! Zeroizing data-key newtype for AWS KMS per-value envelope encryption.
//!
//! Under `key_source = aws_kms` every value is encrypted with a fresh 32-byte
//! AES-256 data key minted by `kms:GenerateDataKey` and recovered by
//! `kms:Decrypt`. The plaintext key must live in memory only for the duration of
//! a single encrypt/decrypt op, so it is held in a [`Zeroizing`] array and the
//! intermediate KMS plaintext buffer (`Blob::into_inner()`) is explicitly wiped.

use anyhow::{Result, anyhow};
use zeroize::{Zeroize, Zeroizing};

/// A 32-byte AES-256 data key held in memory only for a single crypto operation.
///
/// Backed by [`Zeroizing`], so the key bytes are wiped from memory when the value
/// is dropped. Construct from a KMS plaintext buffer with
/// [`DataKey::from_kms_plaintext`], which also wipes the source buffer.
pub struct DataKey(Zeroizing<[u8; 32]>);

impl DataKey {
    /// Build a data key from a KMS plaintext buffer (typically `Blob::into_inner()`),
    /// copying the 32 key bytes into a zeroizing array and wiping the source buffer.
    ///
    /// The source is a [`Zeroizing`] `Vec` so the plaintext is wiped on drop even if
    /// this call fails; the copy is also explicitly zeroized here.
    ///
    /// Fails closed if the plaintext is not exactly 32 bytes (still wiping the source).
    pub fn from_kms_plaintext(mut plaintext: Zeroizing<Vec<u8>>) -> Result<Self> {
        let mut key = [0u8; 32];
        Self::drain_plaintext_into(&mut key, &mut plaintext)?;
        Ok(Self(Zeroizing::new(key)))
    }
    /// Access the raw key bytes for AES-256-GCM.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Copy `src` (a KMS plaintext buffer) into `dst`, then zeroize `src`.
    ///
    /// Split out so the source-wipe contract is unit-testable without moving the
    /// buffer out of the caller's ownership.
    fn drain_plaintext_into(
        dst: &mut [u8; 32],
        src: &mut Vec<u8>,
    ) -> Result<()> {
        if src.len() != 32 {
            let len = src.len();
            src.zeroize();
            return Err(anyhow!("AWS KMS returned a {len}-byte data key; expected 32 bytes for AES-256"));
        }
        dst.copy_from_slice(src);
        src.zeroize();
        Ok(())
    }
}

impl std::fmt::Debug for DataKey {
    fn fmt(
        &self,
        f: &mut std::fmt::Formatter<'_>,
    ) -> std::fmt::Result {
        f.write_str("DataKey(***)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_kms_plaintext_copies_key_bytes() {
        let key = DataKey::from_kms_plaintext(Zeroizing::new(vec![0xAB; 32])).unwrap();
        assert_eq!(key.as_bytes(), &[0xAB; 32]);
    }

    #[test]
    fn from_kms_plaintext_wipes_source_buffer() {
        // The KMS plaintext buffer is the primary residual we must clear.
        let mut src = vec![0xCD; 32];
        let mut dst = [0u8; 32];
        DataKey::drain_plaintext_into(&mut dst, &mut src).unwrap();
        assert_eq!(dst, [0xCD; 32], "the 32 key bytes must be copied out");
        assert!(src.iter().all(|&b| b == 0), "the KMS plaintext buffer must be zeroized after copy, got {src:?}");
    }

    #[test]
    fn from_kms_plaintext_fails_closed_on_wrong_length() {
        let err = DataKey::from_kms_plaintext(Zeroizing::new(vec![1u8; 31])).unwrap_err();
        assert!(
            err.to_string()
                .contains("expected 32 bytes"),
            "wrong-length key must fail closed, got: {err}"
        );
    }

    #[test]
    fn wrong_length_still_wipes_source_buffer() {
        let mut src = vec![0xEE; 31];
        let mut dst = [0u8; 32];
        let err = DataKey::drain_plaintext_into(&mut dst, &mut src).unwrap_err();
        assert!(
            err.to_string()
                .contains("31-byte")
        );
        assert!(src.iter().all(|&b| b == 0), "an over/under-sized KMS plaintext buffer must still be zeroized");
    }

    #[test]
    fn debug_does_not_leak_key_material() {
        let key = DataKey::from_kms_plaintext(Zeroizing::new(vec![0x11; 32])).unwrap();
        let rendered = format!("{key:?}");
        assert_eq!(rendered, "DataKey(***)");
        assert!(!rendered.contains("11"), "debug output must not leak key bytes");
    }
}
