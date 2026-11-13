//! The credentials a passkey sign-in challenge names for a username with no passkey it can sign
//! in with: an unknown username, an account that is not approved, or one without passkeys. They
//! are derived from the username with a key the gateway keeps beside its own keys, so a username
//! gets the same decoys on every challenge and on every instance sharing that storage. Their shape
//! follows stored passkeys: usually one ID of 20 bytes, the length iCloud Keychain and Google
//! Password Manager use, sometimes one of another common length, sometimes two or three, and no
//! transports, which the dashboard does not record. No authenticator holds them, so the sign-in
//! fails as any other does.

use anyhow::{Context, Result};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::path::Path;
use webauthn_rs::prelude::Base64UrlSafeData;
use webauthn_rs_proto::AllowCredentials;
use zeroize::Zeroizing;

/// File, in the VC key directory, holding the decoy credential key.
const KEY_FILE_NAME: &str = "login_decoy_credential_key.json";

/// How many usernames in 256 get two decoys, and how many three; the rest get one.
const TWO_DECOYS_IN_256: u8 = 16;
const THREE_DECOYS_IN_256: u8 = 5;

/// Decoy ID lengths and how many decoys in 256 take each: platform passkeys (iCloud Keychain,
/// Google Password Manager), UUID IDs (some password managers), Windows Hello, and security keys
/// and hardware wallets.
const ID_LENGTHS_IN_256: [(usize, u16); 4] = [(20, 200), (16, 16), (32, 16), (64, 24)];

pub struct DecoyCredentialKey {
    secret: Zeroizing<[u8; 32]>,
}

#[derive(Serialize, Deserialize, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
struct StoredDecoyCredentialKey {
    key: String,
}

impl DecoyCredentialKey {
    /// A new random key from the operating system's generator.
    pub fn generate() -> Result<Self> {
        use rand::TryRngCore;

        let mut secret = Zeroizing::new([0u8; 32]);
        rand::rngs::OsRng
            .try_fill_bytes(secret.as_mut())
            .context("the operating system random number generator is unavailable")?;
        Ok(Self { secret })
    }

    /// The key kept in `directory`, created there on first use; see
    /// [`load_or_create_key`](crate::encryption::secret_file::load_or_create_key).
    pub async fn load_or_create(directory: &Path) -> Result<Self> {
        crate::encryption::secret_file::load_or_create_key(
            &directory.join(KEY_FILE_NAME),
            "login decoy credential key",
            Self::generate,
            Self::to_stored,
            Self::parse,
        )
        .await
    }

    /// The decoy credentials named for `username`.
    pub fn credentials_for(
        &self,
        username: &str,
    ) -> Vec<AllowCredentials> {
        let shape = self.derive(b"shape", 0, username);
        let count = match shape[0] {
            draw if draw < THREE_DECOYS_IN_256 => 3,
            draw if draw < THREE_DECOYS_IN_256 + TWO_DECOYS_IN_256 => 2,
            _ => 1,
        };
        (0..count)
            .map(|index| {
                let length = id_length(shape[1 + index]);
                let id = (0..length.div_ceil(32))
                    .flat_map(|block| self.derive(b"id", index * 8 + block, username))
                    .take(length)
                    .collect::<Vec<u8>>();
                AllowCredentials {
                    type_: "public-key".to_string(),
                    id: Base64UrlSafeData::from(id),
                    transports: None,
                }
            })
            .collect()
    }

    fn derive(
        &self,
        label: &[u8],
        counter: usize,
        username: &str,
    ) -> [u8; 32] {
        let mut mac =
            <Hmac<Sha256> as Mac>::new_from_slice(self.secret.as_ref()).expect("HMAC takes a key of any length");
        mac.update(label);
        mac.update(&(counter as u32).to_be_bytes());
        mac.update(username.as_bytes());
        mac.finalize()
            .into_bytes()
            .into()
    }

    fn parse(stored: &str) -> Result<Self> {
        let stored: StoredDecoyCredentialKey = serde_json::from_str(stored)
            .map_err(|_| anyhow::anyhow!("the file is not a login decoy credential key record"))?;
        let mut secret = Zeroizing::new([0u8; 32]);
        if stored.key.len() != 64 || hex::decode_to_slice(&stored.key, secret.as_mut()).is_err() {
            anyhow::bail!("the key must be 64 hexadecimal characters");
        }
        Ok(Self { secret })
    }

    fn to_stored(&self) -> Result<Zeroizing<String>> {
        let stored = StoredDecoyCredentialKey {
            key: hex::encode(self.secret.as_ref()),
        };
        Ok(Zeroizing::new(serde_json::to_string_pretty(&stored)?))
    }
}

/// The ID length that the draw `byte` picks from [`ID_LENGTHS_IN_256`].
fn id_length(byte: u8) -> usize {
    let mut draw = u16::from(byte);
    for (length, share) in ID_LENGTHS_IN_256 {
        if draw < share {
            return length;
        }
        draw -= share;
    }
    ID_LENGTHS_IN_256[0].0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ids_of(credentials: &[AllowCredentials]) -> Vec<Vec<u8>> {
        credentials
            .iter()
            .map(|credential| {
                credential
                    .id
                    .as_ref()
                    .to_vec()
            })
            .collect()
    }

    #[test]
    fn the_id_length_shares_cover_every_draw() {
        assert_eq!(
            ID_LENGTHS_IN_256
                .iter()
                .map(|(_, share)| share)
                .sum::<u16>(),
            256
        );
        assert_eq!(id_length(0), 20);
        assert_eq!(id_length(199), 20);
        assert_eq!(id_length(200), 16);
        assert_eq!(id_length(216), 32);
        assert_eq!(id_length(232), 64);
        assert_eq!(id_length(255), 64);
    }

    #[test]
    fn a_username_gets_the_same_decoys_every_time() {
        let key = DecoyCredentialKey::generate().unwrap();

        for n in 0..200 {
            let username = format!("user-{n}");
            let first = key.credentials_for(&username);
            let again = key.credentials_for(&username);

            assert_eq!(ids_of(&first), ids_of(&again), "{username}");
            assert!((1..=3).contains(&first.len()), "{username}");
            for credential in &first {
                assert_eq!(credential.type_, "public-key");
                assert_eq!(credential.transports, None);
            }
        }
    }

    #[test]
    fn decoys_are_usually_one_platform_passkey_and_sometimes_more_or_longer() {
        let key = DecoyCredentialKey::generate().unwrap();
        let decoys: Vec<Vec<Vec<u8>>> = (0..4000)
            .map(|n| ids_of(&key.credentials_for(&format!("user-{n}"))))
            .collect();

        let with = |count: usize| {
            decoys
                .iter()
                .filter(|ids| ids.len() == count)
                .count()
        };
        assert!(with(1) > 3400, "one decoy: {}", with(1));
        assert!(with(2) > 100 && with(2) < 450, "two decoys: {}", with(2));
        assert!(with(3) > 20 && with(3) < 200, "three decoys: {}", with(3));

        let lengths: Vec<usize> = decoys
            .iter()
            .flatten()
            .map(Vec::len)
            .collect();
        let of_length = |length: usize| {
            lengths
                .iter()
                .filter(|&&found| found == length)
                .count()
        };
        assert!(of_length(20) * 10 > lengths.len() * 7, "20-byte IDs: {}", of_length(20));
        for length in [16, 32, 64] {
            assert!(of_length(length) > 0, "no {length}-byte ID");
        }
        assert_eq!(of_length(16) + of_length(20) + of_length(32) + of_length(64), lengths.len());
    }

    #[test]
    fn decoy_ids_differ_between_usernames_and_within_one() {
        let key = DecoyCredentialKey::generate().unwrap();

        let ids: Vec<Vec<u8>> = (0..2000)
            .flat_map(|n| ids_of(&key.credentials_for(&format!("user-{n}"))))
            .collect();

        let distinct: std::collections::HashSet<&Vec<u8>> = ids.iter().collect();
        assert_eq!(distinct.len(), ids.len());
    }

    #[test]
    fn another_key_gives_a_username_other_decoys() {
        let one = DecoyCredentialKey::generate().unwrap();
        let other = DecoyCredentialKey::generate().unwrap();

        assert_ne!(ids_of(&one.credentials_for("alice")), ids_of(&other.credentials_for("alice")));
    }

    #[tokio::test]
    async fn the_key_is_kept_across_restarts_in_its_directory() {
        let directory = tempfile::tempdir().unwrap();

        let first = DecoyCredentialKey::load_or_create(directory.path())
            .await
            .unwrap();
        let restarted = DecoyCredentialKey::load_or_create(directory.path())
            .await
            .unwrap();
        let elsewhere = DecoyCredentialKey::load_or_create(
            tempfile::tempdir()
                .unwrap()
                .path(),
        )
        .await
        .unwrap();

        assert_eq!(ids_of(&first.credentials_for("alice")), ids_of(&restarted.credentials_for("alice")));
        assert_ne!(ids_of(&first.credentials_for("alice")), ids_of(&elsewhere.credentials_for("alice")));
    }

    #[tokio::test(start_paused = true)]
    async fn a_damaged_key_file_is_refused_not_replaced() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::write(
            directory
                .path()
                .join(KEY_FILE_NAME),
            "not a key",
        )
        .unwrap();

        let error = match DecoyCredentialKey::load_or_create(directory.path()).await {
            Ok(_) => panic!("a damaged key file must be refused"),
            Err(error) => format!("{error:#}"),
        };

        assert!(error.contains("Invalid login decoy credential key"), "{error}");
        assert_eq!(
            std::fs::read_to_string(
                directory
                    .path()
                    .join(KEY_FILE_NAME)
            )
            .unwrap(),
            "not a key"
        );
    }
}
