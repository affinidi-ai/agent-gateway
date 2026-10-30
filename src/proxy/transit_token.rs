//! Transit Token — carries caller context from the inbound pipeline to the transit pipeline.
//!
//! When an agent makes an outbound call through a transit point, it includes a transit token.
//! This token proves the request originated from an authenticated inbound session and carries
//! the caller's identity context forward.
//!
//! Two modes are supported:
//! - **Embedded**: All context is carried in the token itself, signed but not encrypted, so the
//!   managed agent can read every claim (stateless, larger token).
//! - **Reference**: Context stored server-side; token is a short reference key (not yet implemented).
//!
//! Tokens are HS256 JWTs signed with a random key the gateway creates on its first start and keeps
//! with its own keys, so every instance sharing that storage signs and accepts the same tokens.

use anyhow::{Context, Result};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, decode_header, encode};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// Clock difference tolerated on a token's `iat` and `exp`.
const CLOCK_LEEWAY_SECS: u64 = 5;

/// File, in the VC key directory, holding the transit token signing key.
const KEY_FILE_NAME: &str = "transit_token_key.json";

/// The HS256 key transit tokens are signed with, and the `kid` that names it in every token.
#[derive(Clone)]
pub struct TransitTokenKey {
    kid: String,
    secret: Zeroizing<[u8; 32]>,
}

#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
struct StoredTransitTokenKey {
    kid: String,
    key: String,
}

impl TransitTokenKey {
    /// A new random key and key ID from the operating system's generator.
    pub fn generate() -> Result<Self> {
        use rand::TryRngCore;

        let unavailable = "the operating system random number generator is unavailable";
        let mut secret = Zeroizing::new([0u8; 32]);
        let mut kid = [0u8; 16];
        rand::rngs::OsRng
            .try_fill_bytes(secret.as_mut())
            .context(unavailable)?;
        rand::rngs::OsRng
            .try_fill_bytes(&mut kid)
            .context(unavailable)?;
        Ok(Self { kid: hex::encode(kid), secret })
    }

    /// The key kept in `directory`, created there on first use. Instances starting on one
    /// storage directory at the same moment create one key between them and all use it. A key
    /// file that cannot be read or parsed is an error, never replaced. An existing key file,
    /// such as one a restore wrote, is restricted to its owner.
    pub async fn load_or_create(directory: &Path) -> Result<Self> {
        let path = directory.join(KEY_FILE_NAME);
        let invalid = || format!("Invalid transit token signing key in {}", path.display());
        if let Some(stored) = crate::encryption::secret_file::read_secret_file(&path).await? {
            crate::encryption::secret_file::restrict_secret_file_to_owner(&path).await;
            return Self::parse(&Zeroizing::new(stored)).with_context(invalid);
        }
        let generated = Self::generate()?;
        if crate::encryption::secret_file::create_secret_file(&path, &generated.to_stored()?).await? {
            return Ok(generated);
        }
        let stored = crate::encryption::secret_file::read_secret_file(&path)
            .await?
            .with_context(|| {
                format!("Transit token signing key {} disappeared while it was created", path.display())
            })?;
        Self::parse(&Zeroizing::new(stored)).with_context(invalid)
    }

    fn parse(stored: &str) -> Result<Self> {
        let stored: StoredTransitTokenKey =
            serde_json::from_str(stored).map_err(|_| anyhow::anyhow!("the file is not a transit token key record"))?;
        if stored.kid.is_empty()
            || stored.kid.len() > 64
            || !stored
                .kid
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        {
            anyhow::bail!("the key ID must be 1 to 64 letters, digits, '-' or '_'");
        }
        let mut secret = Zeroizing::new([0u8; 32]);
        if stored.key.len() != 64 || hex::decode_to_slice(&stored.key, secret.as_mut()).is_err() {
            anyhow::bail!("the key must be 64 hexadecimal characters");
        }
        Ok(Self {
            kid: stored.kid.clone(),
            secret,
        })
    }

    fn to_stored(&self) -> Result<Zeroizing<String>> {
        let stored = StoredTransitTokenKey {
            kid: self.kid.clone(),
            key: hex::encode(self.secret.as_ref()),
        };
        Ok(Zeroizing::new(serde_json::to_string_pretty(&stored)?))
    }

    #[cfg(test)]
    pub(crate) fn from_parts(
        kid: &str,
        secret: [u8; 32],
    ) -> Self {
        Self {
            kid: kid.to_string(),
            secret: Zeroizing::new(secret),
        }
    }
}

/// Claims embedded in the transit token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransitTokenClaims {
    /// Token issuer (always the gateway ID).
    pub iss: String,

    /// Subject: the caller DID (who initiated the inbound request).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub: Option<String>,

    /// The surface_id this token was issued for.
    pub surface_id: String,

    /// Issued-at timestamp (Unix seconds).
    pub iat: u64,

    /// Expiry timestamp (Unix seconds).
    pub exp: u64,

    /// Unique token ID (for replay protection in reference mode).
    pub jti: String,

    /// Caller identity source (e.g., "gateway_computed", "verified_presentation").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity_source: Option<String>,

    /// Caller's DNA UAI (if resolved).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub caller_dna_uai: Option<String>,

    /// SHA-256 hash of the authenticated caller identity (for credential vault lookups).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_identity_hash: Option<String>,

    /// Allowlisted caller-context fields captured on the Access Point path and
    /// carried forward for Transit Point Workload Binding. Only the operator-
    /// configured `caller_context_fields` are copied here, verbatim; a value may
    /// be any JSON value. Empty when Workload Binding is not sourcing caller
    /// context from the transit token.
    #[serde(default, skip_serializing_if = "serde_json::Map::is_empty")]
    pub caller_context_fields: serde_json::Map<String, serde_json::Value>,

    /// Allowed transit point names (empty = all allowed).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_transit_points: Vec<String>,

    /// Originating inbound request's trace id. Carried so the outbound (transit)
    /// leg — which the managed agent triggers by echoing this token — continues
    /// the same end-to-end `trace_id` instead of minting a fresh one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trace_id: Option<String>,
}

/// Issues and validates transit tokens.
#[derive(Clone)]
pub struct TransitTokenIssuer {
    /// The key tokens are signed with.
    key: TransitTokenKey,
    /// Gateway ID used as the `iss` claim.
    gateway_id: String,
}

impl TransitTokenIssuer {
    /// Create a new issuer with the given signing key and gateway ID.
    pub fn new(
        key: TransitTokenKey,
        gateway_id: String,
    ) -> Self {
        Self { key, gateway_id }
    }

    /// Issue a transit token for the given surface and caller context, living the
    /// default transit token lifetime.
    #[cfg(test)]
    pub fn issue(
        &self,
        surface_id: &str,
        caller_did: Option<&str>,
        identity_source: Option<&str>,
        caller_dna_uai: Option<&str>,
        user_identity_hash: Option<&str>,
        trace_id: Option<&str>,
        allowed_transit_points: Vec<String>,
    ) -> Result<String> {
        self.issue_with_caller_context(
            surface_id,
            caller_did,
            identity_source,
            caller_dna_uai,
            user_identity_hash,
            trace_id,
            allowed_transit_points,
            serde_json::Map::new(),
            crate::config::agent_surface::DEFAULT_TRANSIT_TOKEN_LIFETIME_SECS,
            crate::config::agent_surface::DEFAULT_TRANSIT_TOKEN_MIN_LIFETIME_SECS,
        )
    }

    /// Issue a transit token that lives `lifetime_secs`, which must be from
    /// `min_lifetime_secs` (the appliance's `transit_token_min_lifetime_secs`) to
    /// 900 seconds, and also carries an
    /// allowlisted set of caller-context fields for Transit Point Workload
    /// Binding. The caller is responsible for having already filtered
    /// `caller_context_fields` down to the operator-configured allowlist; the
    /// issuer copies them verbatim.
    #[allow(clippy::too_many_arguments)]
    pub fn issue_with_caller_context(
        &self,
        surface_id: &str,
        caller_did: Option<&str>,
        identity_source: Option<&str>,
        caller_dna_uai: Option<&str>,
        user_identity_hash: Option<&str>,
        trace_id: Option<&str>,
        allowed_transit_points: Vec<String>,
        caller_context_fields: serde_json::Map<String, serde_json::Value>,
        lifetime_secs: u64,
        min_lifetime_secs: u64,
    ) -> Result<String> {
        use crate::config::agent_surface::MAX_TRANSIT_TOKEN_LIFETIME_SECS;
        if !(min_lifetime_secs..=MAX_TRANSIT_TOKEN_LIFETIME_SECS).contains(&lifetime_secs) {
            anyhow::bail!(
                "transit token lifetime must be from {min_lifetime_secs} to \
                 {MAX_TRANSIT_TOKEN_LIFETIME_SECS} seconds, not {lifetime_secs}"
            );
        }
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("system clock error")?
            .as_secs();

        let claims = TransitTokenClaims {
            iss: self.gateway_id.clone(),
            sub: caller_did.map(|s| s.to_string()),
            surface_id: surface_id.to_string(),
            iat: now,
            exp: now + lifetime_secs,
            jti: uuid::Uuid::new_v4().to_string(),
            identity_source: identity_source.map(|s| s.to_string()),
            caller_dna_uai: caller_dna_uai.map(|s| s.to_string()),
            user_identity_hash: user_identity_hash.map(|s| s.to_string()),
            caller_context_fields,
            trace_id: trace_id.map(|s| s.to_string()),
            allowed_transit_points,
        };

        self.sign(&claims)
    }

    /// Sign `claims` with this issuer's key, naming it in the `kid` header.
    pub(crate) fn sign(
        &self,
        claims: &TransitTokenClaims,
    ) -> Result<String> {
        let mut header = Header::new(Algorithm::HS256);
        header.kid = Some(self.key.kid.clone());
        let key = EncodingKey::from_secret(self.key.secret.as_ref());

        encode(&header, claims, &key).context("failed to encode transit token")
    }

    /// [`Self::validate_for_transit_point`] without the surface and Transit Point checks.
    #[cfg(test)]
    pub fn validate(
        &self,
        token: &str,
        allowed_lifetime_secs: u64,
    ) -> Result<TransitTokenClaims> {
        let claims = self.decode_claims(token)?;
        check_lifetime(&claims, allowed_lifetime_secs)?;
        Ok(claims)
    }

    /// Every check of [`Self::validate_for_transit_point`] that needs only the token.
    fn decode_claims(
        &self,
        token: &str,
    ) -> Result<TransitTokenClaims> {
        let header = decode_header(token).context("transit token validation failed")?;
        if header.kid.as_deref() != Some(self.key.kid.as_str()) {
            anyhow::bail!("transit token is not signed with this gateway's transit token key");
        }
        let key = DecodingKey::from_secret(self.key.secret.as_ref());
        let mut validation = Validation::new(Algorithm::HS256);
        validation.set_issuer(&[&self.gateway_id]);
        validation.validate_exp = true;
        validation.leeway = CLOCK_LEEWAY_SECS;

        let claims = decode::<TransitTokenClaims>(token, &key, &validation)
            .context("transit token validation failed")?
            .claims;

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("system clock error")?
            .as_secs();
        if claims.iat > now.saturating_add(CLOCK_LEEWAY_SECS) {
            anyhow::bail!("transit token is issued in the future");
        }
        if claims.exp <= claims.iat {
            anyhow::bail!("transit token lifetime is not one this gateway issues");
        }
        if claims.jti.is_empty() {
            anyhow::bail!("transit token has no token ID");
        }

        Ok(claims)
    }

    /// Validate a transit token and return the claims. A token whose `kid` does not name this
    /// issuer's key, or that has none, is refused before its signature is checked. A token is
    /// accepted any number of times until it expires; one issued in the future, without a token
    /// ID, issued for another surface than `surface_id`, not opening the Transit Point named
    /// `transit_point_name`, or living longer than `allowed_lifetime_secs` is refused, in that
    /// order, so a token for another surface is refused as such whatever its lifetime.
    ///
    /// `allowed_lifetime_secs` is the lifetime `surface_id` sets when the token is presented, so
    /// shortening it refuses the tokens already issued for longer, and lengthening it keeps the
    /// shorter ones only until their own expiry.
    pub fn validate_for_transit_point(
        &self,
        token: &str,
        surface_id: &str,
        transit_point_name: &str,
        allowed_lifetime_secs: u64,
    ) -> Result<TransitTokenClaims> {
        let claims = self.decode_claims(token)?;

        if claims.surface_id.is_empty() || claims.surface_id != surface_id {
            anyhow::bail!("transit token was issued for another surface");
        }

        // If allowed_transit_points is empty, all are allowed
        if !claims
            .allowed_transit_points
            .is_empty()
            && !claims
                .allowed_transit_points
                .contains(&transit_point_name.to_string())
        {
            anyhow::bail!("transit token not authorized for transit point '{}'", transit_point_name);
        }
        check_lifetime(&claims, allowed_lifetime_secs)?;

        Ok(claims)
    }
}

fn check_lifetime(
    claims: &TransitTokenClaims,
    allowed_lifetime_secs: u64,
) -> Result<()> {
    if claims.exp - claims.iat > allowed_lifetime_secs {
        anyhow::bail!("transit token lives longer than its surface allows");
    }
    Ok(())
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    const LIFETIME: u64 = crate::config::agent_surface::DEFAULT_TRANSIT_TOKEN_LIFETIME_SECS;

    fn test_issuer() -> TransitTokenIssuer {
        TransitTokenIssuer::new(TransitTokenKey::from_parts("test-kid", [7; 32]), "gw-test-001".to_string())
    }

    fn claims_for(
        surface_id: &str,
        iat: u64,
        exp: u64,
    ) -> TransitTokenClaims {
        TransitTokenClaims {
            iss: "gw-test-001".to_string(),
            sub: None,
            surface_id: surface_id.to_string(),
            iat,
            exp,
            jti: uuid::Uuid::new_v4().to_string(),
            identity_source: None,
            caller_dna_uai: None,
            user_identity_hash: Some("victim-hash".to_string()),
            caller_context_fields: serde_json::Map::new(),
            allowed_transit_points: vec![],
            trace_id: None,
        }
    }

    fn now() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    fn sign_with(
        header: Header,
        secret: &[u8],
        claims: &TransitTokenClaims,
    ) -> String {
        encode(&header, claims, &EncodingKey::from_secret(secret)).unwrap()
    }

    #[test]
    fn refuses_a_token_signed_with_the_key_derived_from_the_gateway_domain() {
        use sha2::{Digest, Sha256};

        let issuer = test_issuer();
        let derived = Sha256::new()
            .chain_update(b"transit-token-signing-key:")
            .chain_update(b"gw-test-001")
            .finalize();
        let now = now();
        let claims = claims_for("surf-001", now, now + 300);

        let without_kid = sign_with(Header::new(Algorithm::HS256), &derived, &claims);
        let mut with_kid = Header::new(Algorithm::HS256);
        with_kid.kid = Some("test-kid".to_string());
        let with_our_kid = sign_with(with_kid, &derived, &claims);

        for (token, reason) in [
            (without_kid, "transit token is not signed with this gateway's transit token key"),
            (with_our_kid, "transit token validation failed: InvalidSignature"),
        ] {
            assert_eq!(
                refusal(issuer.validate(&token, LIFETIME)),
                reason,
                "a token signed with the domain-derived key"
            );
        }
    }

    #[test]
    fn refuses_a_token_signed_by_another_gateway() {
        let ours = TransitTokenIssuer::new(TransitTokenKey::generate().unwrap(), "gw-test-001".to_string());
        let theirs = TransitTokenIssuer::new(TransitTokenKey::generate().unwrap(), "gw-test-001".to_string());
        let token = theirs
            .issue("surf-001", None, None, None, Some("victim-hash"), None, vec![])
            .unwrap();

        assert_eq!(
            refusal(ours.validate(&token, LIFETIME)),
            "transit token is not signed with this gateway's transit token key"
        );
        assert_eq!(
            theirs
                .validate(&token, LIFETIME)
                .unwrap()
                .user_identity_hash
                .as_deref(),
            Some("victim-hash")
        );
    }

    #[test]
    fn refuses_a_token_whose_kid_names_another_key() {
        let issuer = test_issuer();
        let mut header = Header::new(Algorithm::HS256);
        header.kid = Some("previous-kid".to_string());
        let now = now();
        let token = sign_with(header, &[7; 32], &claims_for("surf-001", now, now + 300));

        assert_eq!(
            refusal(issuer.validate(&token, LIFETIME)),
            "transit token is not signed with this gateway's transit token key"
        );
    }

    #[test]
    fn refuses_a_token_carrying_our_kid_but_another_secret() {
        let issuer = test_issuer();
        let forger =
            TransitTokenIssuer::new(TransitTokenKey::from_parts("test-kid", [8; 32]), "gw-test-001".to_string());
        let token = forger
            .issue("surf-001", None, None, None, None, None, vec![])
            .unwrap();

        assert_eq!(refusal(issuer.validate(&token, LIFETIME)), "transit token validation failed: InvalidSignature");
    }

    #[test]
    fn issued_tokens_name_the_signing_key() {
        let issuer = test_issuer();
        let token = issuer
            .issue("surf-001", None, None, None, None, None, vec![])
            .unwrap();

        let header = decode_header(&token).unwrap();
        assert_eq!(header.kid.as_deref(), Some("test-kid"));
        assert_eq!(header.alg, Algorithm::HS256);
    }

    #[tokio::test]
    async fn a_new_key_is_created_once_and_reloaded_after_a_restart() {
        let dir = tempfile::tempdir().unwrap();

        let first = TransitTokenKey::load_or_create(dir.path())
            .await
            .unwrap();
        let token = TransitTokenIssuer::new(first, "gw-test-001".to_string())
            .issue("surf-001", None, None, None, None, None, vec![])
            .unwrap();
        let restarted = TransitTokenKey::load_or_create(dir.path())
            .await
            .unwrap();

        let claims = TransitTokenIssuer::new(restarted, "gw-test-001".to_string())
            .validate(&token, LIFETIME)
            .unwrap();
        assert_eq!(claims.surface_id, "surf-001");
        let stored: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(dir.path().join(KEY_FILE_NAME)).unwrap()).unwrap();
        assert_eq!(
            stored["kid"]
                .as_str()
                .map(str::len),
            Some(32)
        );
        assert_eq!(
            stored["key"]
                .as_str()
                .map(str::len),
            Some(64)
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(dir.path().join(KEY_FILE_NAME))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_restored_key_file_is_restricted_to_its_owner_when_loaded() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let key_file = dir.path().join(KEY_FILE_NAME);
        let created = TransitTokenKey::load_or_create(dir.path())
            .await
            .unwrap();
        std::fs::set_permissions(&key_file, std::fs::Permissions::from_mode(0o644)).unwrap();

        let loaded = TransitTokenKey::load_or_create(dir.path())
            .await
            .unwrap();

        assert_eq!(loaded.kid, created.kid);
        assert_eq!(
            std::fs::metadata(&key_file)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }

    #[tokio::test]
    async fn instances_starting_together_on_one_storage_directory_share_one_key() {
        let dir = tempfile::tempdir().unwrap();

        let (active, standby) =
            tokio::join!(TransitTokenKey::load_or_create(dir.path()), TransitTokenKey::load_or_create(dir.path()));
        let active = TransitTokenIssuer::new(active.unwrap(), "gw-test-001".to_string());
        let standby = TransitTokenIssuer::new(standby.unwrap(), "gw-test-001".to_string());

        let token = active
            .issue("surf-001", None, None, None, None, None, vec![])
            .unwrap();
        assert_eq!(
            standby
                .validate(&token, LIFETIME)
                .unwrap()
                .surface_id,
            "surf-001"
        );
    }

    #[tokio::test]
    async fn a_damaged_key_file_stops_the_load_rather_than_being_replaced() {
        for damaged in [
            "not json",
            r#"{"kid":"k1","key":"abcd"}"#,
            r#"{"kid":"k1","key":"zz00000000000000000000000000000000000000000000000000000000000000"}"#,
            r#"{"kid":"","key":"0000000000000000000000000000000000000000000000000000000000000000"}"#,
            r#"{"kid":"k 1","key":"0000000000000000000000000000000000000000000000000000000000000000"}"#,
            r#"{"kid":"k1","key":"0000000000000000000000000000000000000000000000000000000000000000","extra":1}"#,
        ] {
            let dir = tempfile::tempdir().unwrap();
            std::fs::write(dir.path().join(KEY_FILE_NAME), damaged).unwrap();

            let error = TransitTokenKey::load_or_create(dir.path())
                .await
                .err()
                .unwrap_or_else(|| panic!("{damaged} must not load"));

            assert!(
                error
                    .to_string()
                    .contains("Invalid transit token signing key"),
                "{damaged}: {error}"
            );
            assert_eq!(std::fs::read_to_string(dir.path().join(KEY_FILE_NAME)).unwrap(), damaged);
        }
    }

    #[tokio::test]
    async fn the_key_is_stored_encrypted_when_encryption_at_rest_is_enabled() {
        crate::encryption::global::set_test_encryption(
            crate::config::EncryptionConfig {
                enabled: true,
                key_source: crate::config::KeySourceConfig::Environment,
                ..crate::config::EncryptionConfig::default()
            },
            crate::encryption::EncryptionService::new(crate::encryption::KeySource::Raw { key: [9u8; 32] }).unwrap(),
        );
        let dir = tempfile::tempdir().unwrap();

        let created = TransitTokenKey::load_or_create(dir.path())
            .await
            .unwrap();

        let path = dir.path().join(KEY_FILE_NAME);
        assert!(!path.exists(), "the key must not be written in plaintext");
        let on_disk = std::fs::read_to_string(crate::encryption::secret_file::secret_enc_path(&path)).unwrap();
        assert!(!on_disk.contains(&hex::encode(created.secret.as_ref())));
        let reloaded = TransitTokenKey::load_or_create(dir.path())
            .await
            .unwrap();
        assert_eq!(reloaded.kid, created.kid);
        assert_eq!(reloaded.secret.as_ref(), created.secret.as_ref());
    }

    #[test]
    fn test_issue_and_validate() {
        let issuer = test_issuer();

        let token = issuer
            .issue(
                "surf-001",
                Some("did:example:caller"),
                Some("gateway_computed"),
                Some("uai:123"),
                Some("abc123hash"),
                Some("trace-abc-123"),
                vec![],
            )
            .unwrap();

        let claims = issuer
            .validate(&token, LIFETIME)
            .unwrap();
        assert_eq!(claims.iss, "gw-test-001");
        assert_eq!(claims.sub, Some("did:example:caller".to_string()));
        assert_eq!(claims.surface_id, "surf-001");
        assert_eq!(claims.identity_source, Some("gateway_computed".to_string()));
        assert_eq!(claims.caller_dna_uai, Some("uai:123".to_string()));
        assert_eq!(claims.user_identity_hash, Some("abc123hash".to_string()));
        assert_eq!(claims.trace_id, Some("trace-abc-123".to_string()));
        assert!(
            claims
                .allowed_transit_points
                .is_empty()
        );
    }

    #[test]
    fn test_validate_expired_token() {
        let issuer = test_issuer();

        // Manually create a token with exp in the past
        let past = 1000u64; // Unix timestamp 1000 (1970)
        let claims = TransitTokenClaims {
            iss: "gw-test-001".to_string(),
            sub: None,
            surface_id: "surf-001".to_string(),
            iat: past,
            exp: past + 1,
            jti: "expired-jti".to_string(),
            identity_source: None,
            caller_dna_uai: None,
            user_identity_hash: None,
            caller_context_fields: serde_json::Map::new(),
            trace_id: None,
            allowed_transit_points: vec![],
        };

        let token = issuer.sign(&claims).unwrap();

        let result = issuer.validate(&token, LIFETIME);
        assert!(result.is_err(), "expired token should be rejected");
    }

    #[test]
    fn test_validate_for_transit_point_allowed() {
        let issuer = test_issuer();

        let token = issuer
            .issue("surf-001", None, None, None, None, None, vec!["github-api".to_string(), "partner".to_string()])
            .unwrap();

        // Allowed
        let claims = issuer
            .validate_for_transit_point(&token, "surf-001", "github-api", LIFETIME)
            .unwrap();
        assert_eq!(claims.surface_id, "surf-001");

        // Also allowed
        assert!(
            issuer
                .validate_for_transit_point(&token, "surf-001", "partner", LIFETIME)
                .is_ok()
        );

        // Not allowed
        let result = issuer.validate_for_transit_point(&token, "surf-001", "unauthorized-point", LIFETIME);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_for_transit_point_empty_means_all() {
        let issuer = test_issuer();

        let token = issuer
            .issue("surf-001", None, None, None, None, None, vec![])
            .unwrap();

        // Empty allowed_transit_points means all are permitted
        assert!(
            issuer
                .validate_for_transit_point(&token, "surf-001", "any-point", LIFETIME)
                .is_ok()
        );
    }

    #[test]
    fn refuses_a_token_issued_for_another_surface_on_a_transit_point_of_the_same_alias() {
        let issuer = test_issuer();
        let token = issuer
            .issue("surface-a", None, None, None, Some("victim-hash"), None, vec!["partner".to_string()])
            .unwrap();

        let error = issuer
            .validate_for_transit_point(&token, "surface-b", "partner", LIFETIME)
            .unwrap_err();

        assert!(
            error
                .to_string()
                .contains("another surface"),
            "{error}"
        );
        assert!(
            issuer
                .validate_for_transit_point(&token, "surface-a", "partner", LIFETIME)
                .is_ok()
        );
    }

    #[test]
    fn refuses_a_longer_lived_token_for_another_surface_as_issued_for_another_surface() {
        let issuer = test_issuer();
        let now = now();
        let token = issuer
            .sign(&claims_for("surface-b", now, now + 900))
            .unwrap();

        assert_eq!(
            refusal(issuer.validate_for_transit_point(&token, "surface-a", "partner", LIFETIME)),
            "transit token was issued for another surface"
        );
        assert_eq!(
            refusal(issuer.validate_for_transit_point(&token, "surface-b", "partner", LIFETIME)),
            "transit token lives longer than its surface allows"
        );
    }

    /// Why `validated` was refused, with every cause.
    fn refusal(validated: Result<TransitTokenClaims>) -> String {
        format!("{:#}", validated.unwrap_err())
    }

    #[test]
    fn refuses_a_token_without_a_surface() {
        let issuer = test_issuer();
        let now = now();
        let token = issuer
            .sign(&claims_for("", now, now + 300))
            .unwrap();

        assert_eq!(
            refusal(issuer.validate_for_transit_point(&token, "", "partner", LIFETIME)),
            "transit token was issued for another surface"
        );
    }

    #[test]
    fn refuses_tokens_living_longer_than_their_surface_allows_or_issued_in_the_future() {
        let issuer = test_issuer();
        let now = now();
        for (case, iat, exp, reason) in [
            ("thirty days", now, now + 30 * 24 * 3600, "transit token lives longer than its surface allows"),
            ("one second too long", now - 10, now + 291, "transit token lives longer than its surface allows"),
            ("issued in the future", now + 60, now + 300, "transit token is issued in the future"),
            ("expires when issued", now, now, "transit token lifetime is not one this gateway issues"),
            ("expires before it is issued", now, now - 1, "transit token lifetime is not one this gateway issues"),
            ("expired beyond the leeway", now - 300, now - 30, "transit token validation failed: ExpiredSignature"),
        ] {
            let token = issuer
                .sign(&claims_for("surf-001", iat, exp))
                .unwrap();
            assert_eq!(
                refusal(issuer.validate_for_transit_point(&token, "surf-001", "partner", LIFETIME)),
                reason,
                "{case} must be refused for its lifetime"
            );
        }
    }

    #[test]
    fn refuses_a_token_without_a_token_id() {
        let issuer = test_issuer();
        let now = now();
        let mut claims = claims_for("surf-001", now, now + 300);
        claims.jti = String::new();
        let token = issuer.sign(&claims).unwrap();

        assert_eq!(refusal(issuer.validate(&token, LIFETIME)), "transit token has no token ID");
    }

    #[test]
    fn accepts_the_same_token_again_and_again_within_its_lifetime() {
        let issuer = test_issuer();
        let token = issuer
            .issue("surf-001", None, None, None, Some("caller-hash"), None, vec![])
            .unwrap();
        let now = now();
        let near_expiry = issuer
            .sign(&claims_for("surf-001", now - 298, now + 2))
            .unwrap();

        for _ in 0..5 {
            for token in [&token, &near_expiry] {
                assert_eq!(
                    issuer
                        .validate_for_transit_point(token, "surf-001", "partner", LIFETIME)
                        .unwrap()
                        .surface_id,
                    "surf-001"
                );
            }
        }
    }

    fn issue_living(
        issuer: &TransitTokenIssuer,
        lifetime_secs: u64,
    ) -> String {
        issuer
            .issue_with_caller_context(
                "surf-001",
                None,
                None,
                None,
                Some("caller-hash"),
                None,
                vec![],
                serde_json::Map::new(),
                lifetime_secs,
                crate::config::agent_surface::DEFAULT_TRANSIT_TOKEN_MIN_LIFETIME_SECS,
            )
            .unwrap()
    }

    #[test]
    fn issues_tokens_living_the_lifetime_asked_for() {
        let issuer = test_issuer();

        for lifetime in [30, LIFETIME, 600, 900] {
            let claims = issuer
                .validate(&issue_living(&issuer, lifetime), lifetime)
                .unwrap();

            assert_eq!(claims.exp - claims.iat, lifetime);
        }
    }

    #[test]
    fn checks_a_token_against_the_lifetime_its_surface_allows() {
        let issuer = test_issuer();
        let now = now();
        let sign = |iat, exp| {
            issuer
                .sign(&claims_for("surf-001", iat, exp))
                .unwrap()
        };

        let issued_400_seconds_ago = issuer
            .validate_for_transit_point(&sign(now - 400, now + 200), "surf-001", "partner", 600)
            .unwrap();
        assert_eq!((issued_400_seconds_ago.iat, issued_400_seconds_ago.exp), (now - 400, now + 200));
        for (case, iat, exp, reason) in [
            ("past its lifetime", now - 610, now - 10, "transit token validation failed: ExpiredSignature"),
            ("one second longer", now, now + 601, "transit token lives longer than its surface allows"),
        ] {
            assert_eq!(
                refusal(issuer.validate_for_transit_point(&sign(iat, exp), "surf-001", "partner", 600)),
                reason,
                "{case}"
            );
        }
    }

    /// Shortening a surface's lifetime refuses the tokens already issued for longer, and
    /// lengthening it keeps the shorter ones only until their own expiry.
    #[test]
    fn a_changed_lifetime_refuses_longer_tokens_and_never_extends_shorter_ones() {
        let issuer = test_issuer();
        let now = now();

        assert_eq!(
            refusal(issuer.validate(&issue_living(&issuer, 600), 300)),
            "transit token lives longer than its surface allows"
        );
        let kept = issuer
            .validate(&issue_living(&issuer, 300), 600)
            .unwrap();
        assert_eq!(kept.exp - kept.iat, 300);
        let expired = issuer
            .sign(&claims_for("surf-001", now - 310, now - 10))
            .unwrap();
        assert_eq!(refusal(issuer.validate(&expired, 900)), "transit token validation failed: ExpiredSignature");
    }

    #[test]
    fn test_anonymous_caller() {
        let issuer = test_issuer();

        let token = issuer
            .issue("surf-001", None, None, None, None, None, vec![])
            .unwrap();

        let claims = issuer
            .validate(&token, LIFETIME)
            .unwrap();
        assert_eq!(claims.sub, None);
        assert_eq!(claims.identity_source, None);
        assert_eq!(claims.caller_dna_uai, None);
        assert_eq!(claims.user_identity_hash, None);
    }

    // ── Workload Binding: caller-context fields in the transit token ─────────

    #[test]
    fn workload_binding_token_carries_only_configured_caller_context_plus_userhash() {
        let issuer = test_issuer();
        // The caller supplies an already-allowlisted map (scalar + object/array
        // values) plus a stable user hash.
        let mut fields = serde_json::Map::new();
        fields.insert("sub".to_string(), serde_json::json!("alice-subject"));
        fields.insert("email".to_string(), serde_json::json!("alice@example.test"));
        fields.insert("roles".to_string(), serde_json::json!(["admin", "ops"]));
        fields.insert("org".to_string(), serde_json::json!({ "id": "acme", "tier": 3 }));

        let token = issuer
            .issue_with_caller_context(
                "surf-001",
                Some("did:example:alice"),
                Some("jwt_bearer"),
                None,
                Some("sha256-user-hash"),
                None,
                vec!["delta".to_string()],
                fields.clone(),
                LIFETIME,
                crate::config::agent_surface::DEFAULT_TRANSIT_TOKEN_MIN_LIFETIME_SECS,
            )
            .unwrap();

        let claims = issuer
            .validate(&token, LIFETIME)
            .unwrap();
        assert_eq!(claims.caller_context_fields, fields, "fields must be carried verbatim");
        assert_eq!(claims.user_identity_hash, Some("sha256-user-hash".to_string()));
        // No fields beyond what was configured leak in.
        assert_eq!(
            claims
                .caller_context_fields
                .len(),
            4
        );
    }

    #[test]
    fn the_issuer_refuses_a_lifetime_outside_the_bounds() {
        use crate::config::agent_surface::{
            DEFAULT_TRANSIT_TOKEN_MIN_LIFETIME_SECS as MIN_TRANSIT_TOKEN_LIFETIME_SECS, MAX_TRANSIT_TOKEN_LIFETIME_SECS,
        };
        let issuer = test_issuer();
        for lifetime in [0, MIN_TRANSIT_TOKEN_LIFETIME_SECS - 1, MAX_TRANSIT_TOKEN_LIFETIME_SECS + 1, u64::MAX] {
            let result = issuer.issue_with_caller_context(
                "surf-001",
                None,
                None,
                None,
                None,
                None,
                vec![],
                serde_json::Map::new(),
                lifetime,
                crate::config::agent_surface::DEFAULT_TRANSIT_TOKEN_MIN_LIFETIME_SECS,
            );
            assert!(result.is_err(), "{lifetime}");
        }
        for lifetime in [MIN_TRANSIT_TOKEN_LIFETIME_SECS, MAX_TRANSIT_TOKEN_LIFETIME_SECS] {
            let token = issuer
                .issue_with_caller_context(
                    "surf-001",
                    None,
                    None,
                    None,
                    None,
                    None,
                    vec![],
                    serde_json::Map::new(),
                    lifetime,
                    crate::config::agent_surface::DEFAULT_TRANSIT_TOKEN_MIN_LIFETIME_SECS,
                )
                .unwrap();
            assert!(
                issuer
                    .validate(&token, lifetime)
                    .is_ok(),
                "{lifetime}"
            );
        }
    }

    /// The shortest lifetime the issuer mints follows the minimum it is given, both ways.
    #[test]
    fn the_issuers_shortest_lifetime_follows_the_minimum_it_is_given() {
        let issuer = test_issuer();
        let issue = |lifetime: u64, min_lifetime: u64| {
            issuer.issue_with_caller_context(
                "surf-001",
                None,
                None,
                None,
                None,
                None,
                vec![],
                serde_json::Map::new(),
                lifetime,
                min_lifetime,
            )
        };
        assert!(issue(10, 10).is_ok());
        assert!(issue(9, 10).is_err());
        assert!(issue(120, 120).is_ok());
        assert!(issue(119, 120).is_err());
        assert!(
            issue(10, crate::config::agent_surface::DEFAULT_TRANSIT_TOKEN_MIN_LIFETIME_SECS).is_err(),
            "the default floor is 30"
        );
    }

    #[test]
    fn workload_binding_token_preserves_arbitrary_json_values_as_is() {
        let issuer = test_issuer();
        let mut fields = serde_json::Map::new();
        fields.insert("count".to_string(), serde_json::json!(42));
        fields.insert("nested".to_string(), serde_json::json!({ "a": { "b": [1, 2, 3] } }));

        let token = issuer
            .issue_with_caller_context(
                "surf-001",
                None,
                None,
                None,
                None,
                None,
                vec![],
                fields.clone(),
                LIFETIME,
                crate::config::agent_surface::DEFAULT_TRANSIT_TOKEN_MIN_LIFETIME_SECS,
            )
            .unwrap();
        let claims = issuer
            .validate(&token, LIFETIME)
            .unwrap();
        assert_eq!(claims.caller_context_fields["count"], serde_json::json!(42));
        assert_eq!(claims.caller_context_fields["nested"], serde_json::json!({ "a": { "b": [1, 2, 3] } }));
    }

    #[test]
    fn workload_binding_token_omits_caller_context_when_empty() {
        let issuer = test_issuer();
        // Legacy `issue` path carries no caller context.
        let token = issuer
            .issue("surf-001", None, None, None, None, None, vec![])
            .unwrap();
        // The claim is absent from the serialized token (skip_serializing_if).
        let payload = token
            .split('.')
            .nth(1)
            .unwrap();
        use base64::Engine as _;
        let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(payload)
            .unwrap();
        let raw: serde_json::Value = serde_json::from_slice(&decoded).unwrap();
        assert!(
            raw.get("caller_context_fields")
                .is_none(),
            "empty caller context must be omitted from the wire token"
        );
        // And it round-trips to an empty map.
        let claims = issuer
            .validate(&token, LIFETIME)
            .unwrap();
        assert!(
            claims
                .caller_context_fields
                .is_empty()
        );
    }

    #[test]
    fn workload_binding_token_still_authorizes_only_configured_transit_point() {
        let issuer = test_issuer();
        let mut fields = serde_json::Map::new();
        fields.insert("sub".to_string(), serde_json::json!("alice-subject"));

        let token = issuer
            .issue_with_caller_context(
                "surf-001",
                None,
                None,
                None,
                None,
                None,
                vec!["delta".to_string()],
                fields,
                LIFETIME,
                crate::config::agent_surface::DEFAULT_TRANSIT_TOKEN_MIN_LIFETIME_SECS,
            )
            .unwrap();

        // Carrying caller context does not widen transit-point authorization.
        assert!(
            issuer
                .validate_for_transit_point(&token, "surf-001", "delta", LIFETIME)
                .is_ok()
        );
        assert!(
            issuer
                .validate_for_transit_point(&token, "surf-001", "other", LIFETIME)
                .is_err()
        );
    }
}
