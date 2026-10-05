//! Transit Token — carries caller context from the inbound pipeline to the transit pipeline.
//!
//! When an agent makes an outbound call through a transit point, it includes a transit token.
//! This token proves the request originated from an authenticated inbound session and carries
//! the caller's identity context forward.
//!
//! Two modes are supported:
//! - **Embedded**: All context is encrypted into the token itself (stateless, larger token).
//! - **Reference**: Context stored server-side; token is a short reference key (not yet implemented).

use anyhow::{Context, Result};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

/// Default token TTL: 5 minutes (transit should be immediate).
const DEFAULT_TTL_SECS: u64 = 300;

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
    /// HMAC secret for signing tokens.
    signing_key: Vec<u8>,
    /// Gateway ID used as the `iss` claim.
    gateway_id: String,
    /// Token TTL in seconds.
    ttl_secs: u64,
}

impl TransitTokenIssuer {
    /// Create a new issuer with the given HMAC secret and gateway ID.
    pub fn new(
        signing_secret: &[u8],
        gateway_id: String,
    ) -> Self {
        Self {
            signing_key: signing_secret.to_vec(),
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

        let header = Header::new(Algorithm::HS256);
        let key = EncodingKey::from_secret(&self.signing_key);

        encode(&header, &claims, &key).context("failed to encode transit token")
    }

    /// Validate a transit token and return the claims.
    pub fn validate(
        &self,
        token: &str,
    ) -> Result<TransitTokenClaims> {
        let key = DecodingKey::from_secret(&self.signing_key);
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
        TransitTokenIssuer::new(b"test-secret-key-32-bytes-long!!", "gw-test-001".to_string())
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

        let header = Header::new(Algorithm::HS256);
        let key = EncodingKey::from_secret(b"test-secret-key-32-bytes-long!!");
        let token = encode(&header, &claims, &key).unwrap();

        let result = issuer.validate(&token);
        assert!(result.is_err(), "expired token should be rejected");
    }

    #[test]
    fn test_validate_wrong_secret() {
        let issuer = test_issuer();
        let token = issuer
            .issue("surf-001", None, None, None, None, None, vec![])
            .unwrap();

        let wrong_issuer = TransitTokenIssuer::new(b"wrong-secret-key-32-bytes-long!", "gw-test-001".to_string());
        let result = wrong_issuer.validate(&token);
        assert!(result.is_err());
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
