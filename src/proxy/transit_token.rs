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

/// Default token TTL: 5 minutes (transit should be immediate).
const DEFAULT_TTL_SECS: u64 = 300;

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
    /// Token TTL in seconds.
    ttl_secs: u64,
}

impl TransitTokenIssuer {
    /// Create a new issuer with the given signing key and gateway ID.
    pub fn new(
        key: TransitTokenKey,
        gateway_id: String,
    ) -> Self {
        Self {
            key,
            gateway_id,
            ttl_secs: DEFAULT_TTL_SECS,
        }
    }

    /// Create with a custom TTL.
    #[allow(dead_code)]
    pub fn with_ttl(
        mut self,
        ttl_secs: u64,
    ) -> Self {
        self.ttl_secs = ttl_secs;
        self
    }

    /// Issue a transit token for the given surface and caller context.
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
        )
    }

    /// Issue a transit token that also carries an allowlisted set of caller-
    /// context fields for Transit Point Workload Binding. The caller is
    /// responsible for having already filtered `caller_context_fields` down to
    /// the operator-configured allowlist; the issuer copies them verbatim.
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
    ) -> Result<String> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("system clock error")?
            .as_secs();

        let claims = TransitTokenClaims {
            iss: self.gateway_id.clone(),
            sub: caller_did.map(|s| s.to_string()),
            surface_id: surface_id.to_string(),
            iat: now,
            exp: now + self.ttl_secs,
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

    /// Validate a transit token and return the claims. A token whose `kid` does not name this
    /// issuer's key, or that has none, is refused before its signature is checked.
    pub fn validate(
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

        let token_data =
            decode::<TransitTokenClaims>(token, &key, &validation).context("transit token validation failed")?;

        Ok(token_data.claims)
    }

    /// Validate a transit token and check it's authorized for a specific transit point.
    pub fn validate_for_transit_point(
        &self,
        token: &str,
        transit_point_name: &str,
    ) -> Result<TransitTokenClaims> {
        let claims = self.validate(token)?;

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

        Ok(claims)
    }
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

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
        let claims = claims_for("surf-001", now(), now() + 300);

        let without_kid = sign_with(Header::new(Algorithm::HS256), &derived, &claims);
        let mut with_kid = Header::new(Algorithm::HS256);
        with_kid.kid = Some("test-kid".to_string());
        let with_our_kid = sign_with(with_kid, &derived, &claims);

        for token in [without_kid, with_our_kid] {
            assert!(
                issuer
                    .validate(&token)
                    .is_err(),
                "a token signed with the domain-derived key must be refused"
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

        assert!(ours.validate(&token).is_err());
        assert_eq!(
            theirs
                .validate(&token)
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
        let token = sign_with(header, &[7; 32], &claims_for("surf-001", now(), now() + 300));

        let error = issuer
            .validate(&token)
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("not signed with this gateway's transit token key"),
            "{error}"
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

        assert!(
            issuer
                .validate(&token)
                .is_err()
        );
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
            .validate(&token)
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
                .validate(&token)
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
            .validate(&token)
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

        let result = issuer.validate(&token);
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
            .validate_for_transit_point(&token, "github-api")
            .unwrap();
        assert_eq!(claims.surface_id, "surf-001");

        // Also allowed
        assert!(
            issuer
                .validate_for_transit_point(&token, "partner")
                .is_ok()
        );

        // Not allowed
        let result = issuer.validate_for_transit_point(&token, "unauthorized-point");
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
                .validate_for_transit_point(&token, "any-point")
                .is_ok()
        );
    }

    #[test]
    fn test_anonymous_caller() {
        let issuer = test_issuer();

        let token = issuer
            .issue("surf-001", None, None, None, None, None, vec![])
            .unwrap();

        let claims = issuer
            .validate(&token)
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
            )
            .unwrap();

        let claims = issuer
            .validate(&token)
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
    fn workload_binding_token_preserves_arbitrary_json_values_as_is() {
        let issuer = test_issuer();
        let mut fields = serde_json::Map::new();
        fields.insert("count".to_string(), serde_json::json!(42));
        fields.insert("nested".to_string(), serde_json::json!({ "a": { "b": [1, 2, 3] } }));

        let token = issuer
            .issue_with_caller_context("surf-001", None, None, None, None, None, vec![], fields.clone())
            .unwrap();
        let claims = issuer
            .validate(&token)
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
            .validate(&token)
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
            .issue_with_caller_context("surf-001", None, None, None, None, None, vec!["delta".to_string()], fields)
            .unwrap();

        // Carrying caller context does not widen transit-point authorization.
        assert!(
            issuer
                .validate_for_transit_point(&token, "delta")
                .is_ok()
        );
        assert!(
            issuer
                .validate_for_transit_point(&token, "other")
                .is_err()
        );
    }
}
