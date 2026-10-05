//! ID-JAG — Identity Assertion JWT Authorization Grant
//! (`draft-ietf-oauth-identity-assertion-authz-grant`).
//!
//! An ID-JAG is a short-lived, audience-restricted JWT authorization grant. The
//! gateway plays two roles:
//!
//! - **IdP role** — [`build_id_jag_claims`] mints an ID-JAG (issued via the
//!   token-exchange path with `requested_token_type = id-jag`).
//! - **Resource-AS role** — [`validate_id_jag`] structurally validates an
//!   inbound ID-JAG (presented via the RFC 7523 `jwt-bearer` grant) before the
//!   gateway mints a scoped access token the Target trusts.
//!
//! Pure and IO-free (`issued_at`/`now`/`jti` injected); signature verification
//! is the handler's job via the JWT verifier.

use serde_json::{Map, Value};

use crate::sts::errors::StsError;

/// Inputs for [`build_id_jag_claims`].
#[derive(Debug, Clone)]
pub struct IdJagParams<'a> {
    /// The gateway (acting as IdP) issuer identifier.
    pub issuer: &'a str,
    /// Immutable subject identifier (the user/caller on whose behalf).
    pub subject: &'a str,
    /// The resource authorization server this grant is bound to.
    pub audience: &'a str,
    /// The requesting application/agent.
    pub client_id: &'a str,
    pub scopes: &'a [String],
    pub issued_at: u64,
    pub ttl_secs: u64,
    pub jti: &'a str,
    /// RFC 8693 §4.1 delegation actor (`act`) to embed — the party acting on
    /// behalf of the subject (e.g. the agent DID). `None` embeds no `act`.
    pub act: Option<Value>,
}

/// Build the claim set for an issued ID-JAG.
pub fn build_id_jag_claims(p: IdJagParams<'_>) -> Value {
    let mut claims = Map::new();
    claims.insert("iss".to_string(), Value::String(p.issuer.to_string()));
    claims.insert("sub".to_string(), Value::String(p.subject.to_string()));
    claims.insert("aud".to_string(), Value::String(p.audience.to_string()));
    claims.insert("client_id".to_string(), Value::String(p.client_id.to_string()));
    if !p.scopes.is_empty() {
        claims.insert("scope".to_string(), Value::String(p.scopes.join(" ")));
    }
    claims.insert("iat".to_string(), Value::Number(p.issued_at.into()));
    claims.insert("exp".to_string(), Value::Number((p.issued_at + p.ttl_secs).into()));
    claims.insert("jti".to_string(), Value::String(p.jti.to_string()));
    if let Some(act) = p.act {
        claims.insert("act".to_string(), act);
    }
    Value::Object(claims)
}

/// The validated, structurally-sound claims of an inbound ID-JAG.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdJagClaims {
    pub issuer: String,
    pub subject: String,
    pub audience: Vec<String>,
    pub client_id: String,
    pub scopes: Vec<String>,
    /// Unique grant id — required, and consumed once via the single-use guard.
    pub jti: String,
    /// Grant expiry (unix seconds); bounds how long the single-use record is held.
    pub expires_at: u64,
    /// RFC 8693 §4.1 delegation actor (`act`) carried by the grant, preserved
    /// verbatim into the redeemed access token. `None` for a legacy ID-JAG.
    pub act: Option<Value>,
}

/// Whether an OAuth `aud` claim (string or array of strings) contains `expected`.
fn audience_contains(
    aud: &Value,
    expected: &str,
) -> bool {
    match aud {
        Value::String(s) => s == expected,
        Value::Array(items) => items
            .iter()
            .any(|v| v.as_str() == Some(expected)),
        _ => false,
    }
}

/// Normalize an OAuth `aud` claim into a vector of strings.
fn normalize_audience(aud: &Value) -> Vec<String> {
    match aud {
        Value::String(s) => vec![s.clone()],
        Value::Array(items) => items
            .iter()
            .filter_map(|v| {
                v.as_str()
                    .map(|s| s.to_string())
            })
            .collect(),
        _ => Vec::new(),
    }
}

/// Structurally validate an inbound ID-JAG's claims (signature verification is
/// performed separately by the JWT verifier).
///
/// Enforces: `iss`/`sub`/`client_id` present and non-empty; `aud` contains
/// `expected_audience` (this gateway as the resource AS); `exp` present and in
/// the future relative to `now`; `nbf`, when present, not in the future; and a
/// non-empty `jti` (required for single-use enforcement). On any failure
/// returns `invalid_grant`.
pub fn validate_id_jag(
    claims: &Value,
    expected_audience: &str,
    now: u64,
) -> Result<IdJagClaims, StsError> {
    let issuer = claims
        .get("iss")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| StsError::InvalidGrant("ID-JAG missing iss".to_string()))?
        .to_string();

    let subject = claims
        .get("sub")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| StsError::InvalidGrant("ID-JAG missing sub".to_string()))?
        .to_string();

    let aud = claims
        .get("aud")
        .ok_or_else(|| StsError::InvalidGrant("ID-JAG missing aud".to_string()))?;
    if !audience_contains(aud, expected_audience) {
        return Err(StsError::InvalidGrant("ID-JAG aud does not include this authorization server".to_string()));
    }

    let exp = claims
        .get("exp")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| StsError::InvalidGrant("ID-JAG missing or malformed exp".to_string()))?;
    if exp <= now {
        return Err(StsError::InvalidGrant("ID-JAG has expired".to_string()));
    }

    if let Some(nbf) = claims
        .get("nbf")
        .and_then(|v| v.as_u64())
        && nbf > now
    {
        return Err(StsError::InvalidGrant("ID-JAG is not yet valid (nbf)".to_string()));
    }

    let jti = claims
        .get("jti")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| StsError::InvalidGrant("ID-JAG missing jti".to_string()))?
        .to_string();

    let client_id = claims
        .get("client_id")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| StsError::InvalidGrant("ID-JAG missing client_id".to_string()))?
        .to_string();

    let scopes = claims
        .get("scope")
        .and_then(|v| v.as_str())
        .map(|s| {
            s.split_whitespace()
                .map(|p| p.to_string())
                .collect()
        })
        .unwrap_or_default();

    Ok(IdJagClaims {
        issuer,
        subject,
        audience: normalize_audience(aud),
        client_id,
        scopes,
        jti,
        expires_at: exp,
        act: claims.get("act").cloned(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn build_id_jag_has_required_claims() {
        let scopes = vec!["a".to_string(), "b".to_string()];
        let claims = build_id_jag_claims(IdJagParams {
            issuer: "did:webvh:example:gw",
            subject: "user-123",
            audience: "https://resource.example",
            client_id: "agent0",
            scopes: &scopes,
            issued_at: 1_000,
            ttl_secs: 120,
            jti: "jti-x",
            act: None,
        });
        assert_eq!(claims["iss"], "did:webvh:example:gw");
        assert_eq!(claims["sub"], "user-123");
        assert_eq!(claims["aud"], "https://resource.example");
        assert_eq!(claims["client_id"], "agent0");
        assert_eq!(claims["scope"], "a b");
        assert_eq!(claims["iat"], 1_000);
        assert_eq!(claims["exp"], 1_120);
        assert_eq!(claims["jti"], "jti-x");
        assert!(claims.get("act").is_none());
    }

    #[test]
    fn build_id_jag_embeds_act_and_validate_extracts_it() {
        let scopes = vec!["reports.read".to_string()];
        let act = json!({ "sub": "did:webvh:agent" });
        let claims = build_id_jag_claims(IdJagParams {
            issuer: "did:webvh:example:gw",
            subject: "user-123",
            audience: "https://gw.example",
            client_id: "agent0",
            scopes: &scopes,
            issued_at: 1_000,
            ttl_secs: 120,
            jti: "jti-act",
            act: Some(act.clone()),
        });
        assert_eq!(claims["act"], act);
        let parsed = validate_id_jag(&claims, "https://gw.example", 1_000).expect("valid");
        assert_eq!(parsed.act, Some(act));
    }

    #[test]
    fn validate_id_jag_happy_path_string_aud() {
        let claims = json!({
            "iss": "https://idp.example",
            "sub": "user-123",
            "aud": "https://gw.example",
            "client_id": "agent0",
            "scope": "reports.read reports.write",
            "jti": "grant-1",
            "exp": 2_000
        });
        let parsed = validate_id_jag(&claims, "https://gw.example", 1_000).expect("valid");
        assert_eq!(parsed.issuer, "https://idp.example");
        assert_eq!(parsed.subject, "user-123");
        assert_eq!(parsed.audience, vec!["https://gw.example".to_string()]);
        assert_eq!(parsed.client_id, "agent0");
        assert_eq!(parsed.scopes, vec!["reports.read".to_string(), "reports.write".to_string()]);
        assert_eq!(parsed.jti, "grant-1");
        assert_eq!(parsed.expires_at, 2_000);
        assert!(parsed.act.is_none());
    }

    #[test]
    fn validate_id_jag_accepts_array_aud() {
        let claims = json!({
            "iss": "https://idp.example",
            "sub": "u",
            "aud": ["https://other.example", "https://gw.example"],
            "client_id": "agent0",
            "jti": "grant-2",
            "exp": 2_000
        });
        let parsed = validate_id_jag(&claims, "https://gw.example", 1_000).expect("valid");
        assert_eq!(parsed.audience.len(), 2);
    }

    #[test]
    fn validate_id_jag_rejects_wrong_audience() {
        let claims = json!({ "iss": "i", "sub": "u", "aud": "https://elsewhere.example", "exp": 2_000 });
        let err = validate_id_jag(&claims, "https://gw.example", 1_000).unwrap_err();
        assert_eq!(err.error_code(), "invalid_grant");
    }

    #[test]
    fn validate_id_jag_rejects_expired() {
        let claims = json!({ "iss": "i", "sub": "u", "aud": "https://gw.example", "exp": 500 });
        let err = validate_id_jag(&claims, "https://gw.example", 1_000).unwrap_err();
        assert_eq!(err.error_code(), "invalid_grant");
        assert!(
            err.description()
                .contains("expired")
        );
    }

    #[test]
    fn validate_id_jag_rejects_future_nbf() {
        let claims = json!({ "iss": "i", "sub": "u", "aud": "https://gw.example", "exp": 5_000, "nbf": 4_000 });
        let err = validate_id_jag(&claims, "https://gw.example", 1_000).unwrap_err();
        assert_eq!(err.error_code(), "invalid_grant");
    }

    #[test]
    fn validate_id_jag_requires_iss_sub_exp() {
        let base = json!({ "iss": "i", "sub": "u", "aud": "https://gw.example", "client_id": "agent0", "jti": "g", "exp": 5_000 });
        for missing in ["iss", "sub", "exp", "aud", "client_id", "jti"] {
            let mut c = base.clone();
            c.as_object_mut()
                .unwrap()
                .remove(missing);
            let err = validate_id_jag(&c, "https://gw.example", 1_000).unwrap_err();
            assert_eq!(err.error_code(), "invalid_grant", "missing {missing} must be invalid_grant");
        }
    }
}
