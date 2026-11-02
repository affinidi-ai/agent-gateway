//! Pending connects: the gateway's half of an external consent.
//!
//! Another system runs the browser leg of an OAuth authorization code grant
//! for a binding with `consent_mode: external`. It starts a connect, which
//! the gateway keeps as a pending connect holding the PKCE verifier, and gets
//! back only the S256 challenge. Once the person has consented, it hands the
//! authorization code to the gateway, which claims the pending connect once,
//! redeems the code with its own verifier, and keeps the grant. The verifier
//! never leaves the gateway, so a code is useless to anyone who sees it.
//!
//! A pending connect is kept in the vault, encrypted at rest and under the
//! vault's lock, for ten minutes. Its id is filed under its binding and its
//! principal ([`super::grants::GrantKey::connect_id_prefix`]) and names when
//! it expires, so the connects open for one binding, and for each principal
//! of it, are counted from their file names alone, reading no connect. A
//! binding has at most [`MAX_PENDING_CONNECTS_PER_BINDING`] open, each
//! principal at most [`MAX_PENDING_CONNECTS_PER_PRINCIPAL`]. Claiming one moves
//! it, with its verifier wiped, to the claimed connects, where a second claim
//! finds it and is refused, so a code is redeemed at most once.

use base64::Engine as _;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::grants::{GrantBinding, GrantKey};
use crate::storage::filesystem::StorableEntity;

/// The directory of the vault that holds pending connects, excluded from
/// storage exports.
pub const PENDING_CONNECTS_DIRECTORY: &str = "pending_connects";

/// The directory, within [`PENDING_CONNECTS_DIRECTORY`], of the connects
/// claimed, kept until they expire so a second claim is answered as already
/// used.
pub const CLAIMED_CONNECTS_DIRECTORY: &str = "claimed";

/// How long a connect may wait for its authorization code.
pub const PENDING_CONNECT_LIFETIME_SECS: i64 = 600;

/// The most connects one binding may have open at once.
pub const MAX_PENDING_CONNECTS_PER_BINDING: usize = 32;

/// The most connects one principal of a binding may have open at once: its
/// share of [`MAX_PENDING_CONNECTS_PER_BINDING`], so one caller who reopens
/// the connect link never blocks the binding's other callers.
pub const MAX_PENDING_CONNECTS_PER_PRINCIPAL: usize = 4;

/// A connect waiting for its authorization code.
#[derive(Clone, Serialize, Deserialize)]
pub struct PendingConnect {
    /// [`super::grants::new_connect_id`] of its grant's key and expiry.
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
    pub surface_id: String,
    pub hop: String,
    pub credential_provider_id: String,
    /// [`super::grants::OWNER_PRINCIPAL`], or the caller's identity hash.
    pub principal: String,
    /// The scopes asked for; the grant may hold no others.
    pub scopes: Vec<String>,
    /// The redirect URI the authorization request named, sent again with the
    /// code.
    pub redirect_uri: String,
    /// The PKCE verifier, until the connect is claimed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code_verifier: Option<String>,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    /// When the connect was claimed, so a second claim is refused.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claimed_at: Option<DateTime<Utc>>,
}

impl std::fmt::Debug for PendingConnect {
    fn fmt(
        &self,
        formatter: &mut std::fmt::Formatter<'_>,
    ) -> std::fmt::Result {
        formatter
            .debug_struct("PendingConnect")
            .field("id", &self.id)
            .field("tenant_id", &self.tenant_id)
            .field("surface_id", &self.surface_id)
            .field("hop", &self.hop)
            .field("credential_provider_id", &self.credential_provider_id)
            .field("principal", &self.principal)
            .field("scopes", &self.scopes)
            .field("redirect_uri", &self.redirect_uri)
            .field(
                "code_verifier",
                &self
                    .code_verifier
                    .as_ref()
                    .map(|_| "[REDACTED]"),
            )
            .field("created_at", &self.created_at)
            .field("expires_at", &self.expires_at)
            .field("claimed_at", &self.claimed_at)
            .finish()
    }
}

impl StorableEntity for PendingConnect {
    fn id(&self) -> &str {
        &self.id
    }
}

impl PendingConnect {
    /// A new pending connect for the grant `key` will be kept under, open
    /// from `now` for [`PENDING_CONNECT_LIFETIME_SECS`], with a fresh
    /// verifier, and the verifier's S256 challenge.
    pub fn start(
        key: &GrantKey,
        scopes: Vec<String>,
        redirect_uri: String,
        now: DateTime<Utc>,
    ) -> (Self, String) {
        let verifier = new_code_verifier();
        let challenge = code_challenge(&verifier);
        let expires_at = now + chrono::Duration::seconds(PENDING_CONNECT_LIFETIME_SECS);
        let connect = Self {
            id: super::grants::new_connect_id(key, expires_at),
            tenant_id: key.tenant_id.clone(),
            surface_id: key.surface_id.clone(),
            hop: key.hop.clone(),
            credential_provider_id: key
                .credential_provider_id
                .clone(),
            principal: key.principal.clone(),
            scopes,
            redirect_uri,
            code_verifier: Some(verifier),
            created_at: now,
            expires_at,
            claimed_at: None,
        };
        (connect, challenge)
    }

    /// The key of the grant the connect is for.
    pub fn key(&self) -> GrantKey {
        GrantKey {
            tenant_id: self.tenant_id.clone(),
            surface_id: self.surface_id.clone(),
            hop: self.hop.clone(),
            credential_provider_id: self
                .credential_provider_id
                .clone(),
            principal: self.principal.clone(),
        }
    }

    /// The binding the connect is for.
    pub fn binding(&self) -> GrantBinding {
        self.key().binding()
    }
}

/// What claiming a pending connect came to.
#[derive(Debug)]
pub enum ConnectClaim {
    /// The connect was open, and is now claimed: it carries its verifier,
    /// which is no longer stored.
    Claimed(Box<PendingConnect>),
    /// The connect was claimed before.
    AlreadyUsed,
    /// The connect expired before it was claimed; it is removed.
    Expired,
    /// No connect has this id.
    NotFound,
}

/// The binding has as many connects open as it may.
#[derive(Debug, Clone, Copy, thiserror::Error)]
#[error("This binding already has as many connects waiting for consent as it may")]
pub struct TooManyPendingConnects;

/// A PKCE code verifier (RFC 7636): 32 random bytes, base64url without
/// padding, so 43 characters.
fn new_code_verifier() -> String {
    use rand::RngCore as _;
    let mut random = zeroize::Zeroizing::new([0u8; 32]);
    rand::rng().fill_bytes(random.as_mut());
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(random.as_ref())
}

/// The S256 code challenge of `verifier`: base64url, without padding, of its
/// SHA-256.
pub fn code_challenge(verifier: &str) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The verifier is 43 characters of base64url, never the same twice, and
    /// the challenge is its S256, as RFC 7636 appendix B computes it.
    #[test]
    fn a_connect_holds_a_fresh_verifier_and_answers_only_its_s256_challenge() {
        assert_eq!(
            code_challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
        let key = super::super::grants::tests::key();
        let now = Utc::now();
        let (first, challenge) =
            PendingConnect::start(&key, vec!["read".into()], "https://boris.example/cb".into(), now);
        let (second, _) = PendingConnect::start(&key, vec!["read".into()], "https://boris.example/cb".into(), now);
        let verifier = first
            .code_verifier
            .clone()
            .unwrap();
        assert_eq!(verifier.len(), 43);
        assert!(
            verifier
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
        );
        assert_ne!(first.code_verifier, second.code_verifier);
        assert_ne!(first.id, second.id);
        assert_eq!(challenge, code_challenge(&verifier));
        assert_ne!(challenge, verifier);
        assert_eq!(first.key(), key);
        assert_eq!(first.expires_at - now, chrono::Duration::minutes(10));
        assert_eq!(
            super::super::grants::connect_expiry(&first.id),
            chrono::DateTime::from_timestamp(first.expires_at.timestamp(), 0),
            "the id names when the connect expires"
        );
        let shown = format!("{first:?}");
        assert!(!shown.contains(&verifier), "{shown}");
    }
}
