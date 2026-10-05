//! Pure RFC 8693 token-exchange logic: request validation, delegation-chain
//! (`act`) composition, issued-claim construction, scope narrowing, TTL capping.
//!
//! Everything here is deterministic and free of crypto/IO (`issued_at` and `jti`
//! are injected) so it can be unit-tested in isolation. The handler
//! (`handlers.rs`) verifies tokens, runs policy, and signs; this module decides
//! *what* claims the issued token carries.

use serde_json::{Map, Value};

use crate::sts::errors::StsError;
use crate::sts::types::{TokenEndpointForm, TokenExchangeRequest, TokenType};

/// Extract `(sub, act)` from a verified assertion's claim set. `act` is cloned
/// through verbatim so an existing delegation chain is preserved when the
/// gateway layers a new actor on top.
pub fn extract_subject_and_act(claims: &Value) -> (Option<String>, Option<Value>) {
    let sub = claims
        .get("sub")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let act = claims.get("act").cloned();
    (sub, act)
}

/// Compose the RFC 8693 §4.1 `act` (actor) claim.
///
/// When `actor_sub` is present it becomes the current (outermost) actor and any
/// `subject_act` chain nests beneath it. When `actor_sub` is absent the subject's
/// existing chain (if any) passes through unchanged — impersonation semantics.
pub fn compose_delegation_chain(
    subject_act: Option<Value>,
    actor_sub: Option<&str>,
) -> Option<Value> {
    match actor_sub {
        Some(actor) => {
            let mut act = Map::new();
            act.insert("sub".to_string(), Value::String(actor.to_string()));
            if let Some(prior) = subject_act {
                act.insert("act".to_string(), prior);
            }
            Some(Value::Object(act))
        }
        None => subject_act,
    }
}

/// Inputs for [`build_access_token_claims`].
#[derive(Debug, Clone)]
pub struct AccessTokenParams<'a> {
    pub issuer: &'a str,
    pub subject: &'a str,
    pub subject_act: Option<Value>,
    pub actor_sub: Option<&'a str>,
    pub client_id: Option<&'a str>,
    pub audience: Option<&'a str>,
    pub scopes: &'a [String],
    pub issued_at: u64,
    pub ttl_secs: u64,
    pub jti: &'a str,
}

/// Build the claim set for an issued access token, including the `act`
/// delegation chain. The gateway is the sole authority for `iss`/`iat`/`exp`/
/// `jti`/`act`; a client can never inject them.
pub fn build_access_token_claims(p: AccessTokenParams<'_>) -> Value {
    let mut claims = Map::new();
    claims.insert("iss".to_string(), Value::String(p.issuer.to_string()));
    claims.insert("sub".to_string(), Value::String(p.subject.to_string()));
    if let Some(aud) = p.audience {
        claims.insert("aud".to_string(), Value::String(aud.to_string()));
    }
    if let Some(cid) = p.client_id {
        claims.insert("client_id".to_string(), Value::String(cid.to_string()));
    }
    if !p.scopes.is_empty() {
        claims.insert("scope".to_string(), Value::String(p.scopes.join(" ")));
    }
    claims.insert("iat".to_string(), Value::Number(p.issued_at.into()));
    claims.insert("exp".to_string(), Value::Number((p.issued_at + p.ttl_secs).into()));
    claims.insert("jti".to_string(), Value::String(p.jti.to_string()));
    if let Some(act) = compose_delegation_chain(p.subject_act, p.actor_sub) {
        claims.insert("act".to_string(), act);
    }
    Value::Object(claims)
}

/// The set of `requested_token_type`s the STS can issue as an access-token-shaped
/// JWT. `id-jag` is handled on a separate path (`id_jag.rs`).
fn is_access_token_shaped(t: TokenType) -> bool {
    matches!(t, TokenType::AccessToken | TokenType::Jwt)
}

/// Validate a raw token-endpoint form into a typed token-exchange request.
///
/// Assumes the caller has already routed `grant_type=token-exchange`. Enforces
/// required parameters, token-type parseability, and the actor_token/
/// actor_token_type pairing (RFC 8693 §2.1).
pub fn validate_token_exchange(form: &TokenEndpointForm) -> Result<TokenExchangeRequest, StsError> {
    let subject_token = form
        .subject_token
        .as_deref()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| StsError::InvalidRequest("subject_token is required".to_string()))?
        .to_string();

    let subject_token_type_urn = form
        .subject_token_type
        .as_deref()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| StsError::InvalidRequest("subject_token_type is required".to_string()))?;
    let subject_token_type = TokenType::from_urn(subject_token_type_urn)
        .ok_or_else(|| StsError::UnsupportedTokenType(subject_token_type_urn.to_string()))?;

    // actor_token and actor_token_type must appear together (RFC 8693 §2.1).
    let (actor_token, actor_token_type) = match (&form.actor_token, &form.actor_token_type) {
        (Some(tok), Some(ty)) if !tok.is_empty() && !ty.is_empty() => {
            let parsed = TokenType::from_urn(ty).ok_or_else(|| StsError::UnsupportedTokenType(ty.clone()))?;
            (Some(tok.clone()), Some(parsed))
        }
        (Some(tok), None) if !tok.is_empty() => {
            return Err(StsError::InvalidRequest(
                "actor_token_type is required when actor_token is present".to_string(),
            ));
        }
        (None, Some(_)) => {
            return Err(StsError::InvalidRequest(
                "actor_token_type is only valid together with actor_token".to_string(),
            ));
        }
        _ => (None, None),
    };

    // requested_token_type defaults to access_token (RFC 8693 §2.1).
    let requested_token_type = match form
        .requested_token_type
        .as_deref()
    {
        None | Some("") => TokenType::AccessToken,
        Some(urn) => TokenType::from_urn(urn).ok_or_else(|| StsError::UnsupportedTokenType(urn.to_string()))?,
    };
    if !is_access_token_shaped(requested_token_type) && requested_token_type != TokenType::IdJag {
        return Err(StsError::UnsupportedTokenType(format!(
            "cannot issue requested_token_type {}",
            requested_token_type.as_urn()
        )));
    }

    let scopes = form
        .scope
        .as_deref()
        .map(parse_scope)
        .unwrap_or_default();

    Ok(TokenExchangeRequest {
        subject_token,
        subject_token_type,
        actor_token,
        actor_token_type,
        requested_token_type,
        resource: form
            .resource
            .clone()
            .filter(|s| !s.is_empty()),
        audience: form
            .audience
            .clone()
            .filter(|s| !s.is_empty()),
        scopes,
    })
}

/// Split a space-delimited `scope` string into individual scope tokens.
pub fn parse_scope(scope: &str) -> Vec<String> {
    scope
        .split_whitespace()
        .map(|s| s.to_string())
        .collect()
}

/// Narrow requested scopes against an allowlist.
///
/// An empty `allowed` list means the connection is unrestricted and the
/// requested scopes pass through. Otherwise every requested scope must be a
/// member of `allowed`, else `invalid_scope`.
pub fn resolve_scopes(
    requested: &[String],
    allowed: &[String],
) -> Result<Vec<String>, StsError> {
    if allowed.is_empty() {
        return Ok(requested.to_vec());
    }
    for scope in requested {
        if !allowed
            .iter()
            .any(|a| a == scope)
        {
            return Err(StsError::InvalidScope(format!("scope not permitted: {scope}")));
        }
    }
    Ok(requested.to_vec())
}

/// The effective token TTL: the requested value (or `default`) capped at `max`.
pub fn effective_ttl(
    requested: Option<u64>,
    default: u64,
    max: u64,
) -> u64 {
    requested
        .unwrap_or(default)
        .min(max)
}

/// Constrain requested scopes to a ceiling — the scopes an upstream grant (e.g.
/// an ID-JAG) actually authorized. A requested scope outside the ceiling is
/// dropped (standard OAuth scope-narrowing), so redemption can never widen the
/// grant. An empty ceiling imposes no additional restriction (the grant did not
/// enumerate scopes; the client allowlist still applies afterward).
pub fn ceiling_scopes(
    requested: &[String],
    ceiling: &[String],
) -> Vec<String> {
    if ceiling.is_empty() {
        return requested.to_vec();
    }
    requested
        .iter()
        .filter(|s| {
            ceiling
                .iter()
                .any(|c| c == *s)
        })
        .cloned()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sts::types::{TOKEN_TYPE_ID_JAG, TOKEN_TYPE_JWT, TOKEN_TYPE_REFRESH_TOKEN};
    use serde_json::json;

    fn form(subject_token_type: &str) -> TokenEndpointForm {
        TokenEndpointForm {
            subject_token: Some("subject.jwt.token".to_string()),
            subject_token_type: Some(subject_token_type.to_string()),
            ..Default::default()
        }
    }

    #[test]
    fn extract_subject_and_act_reads_both() {
        let claims = json!({ "sub": "did:example:user", "act": { "sub": "did:example:agent" } });
        let (sub, act) = extract_subject_and_act(&claims);
        assert_eq!(sub.as_deref(), Some("did:example:user"));
        assert_eq!(act, Some(json!({ "sub": "did:example:agent" })));
    }

    #[test]
    fn compose_chain_no_actor_passes_subject_act_through() {
        assert_eq!(compose_delegation_chain(None, None), None);
        let prior = json!({ "sub": "did:example:prior" });
        assert_eq!(compose_delegation_chain(Some(prior.clone()), None), Some(prior));
    }

    #[test]
    fn compose_chain_single_actor_no_prior() {
        let act = compose_delegation_chain(None, Some("did:example:agent")).expect("act present");
        assert_eq!(act, json!({ "sub": "did:example:agent" }));
    }

    #[test]
    fn compose_chain_nests_prior_actor_under_new_actor() {
        let subject_act = json!({ "sub": "did:example:assistant" });
        let act = compose_delegation_chain(Some(subject_act), Some("did:example:analyst")).expect("act");
        assert_eq!(act, json!({ "sub": "did:example:analyst", "act": { "sub": "did:example:assistant" } }));
    }

    #[test]
    fn build_claims_full_shape() {
        let scopes = vec!["reports.read".to_string()];
        let claims = build_access_token_claims(AccessTokenParams {
            issuer: "did:webvh:example:gw",
            subject: "did:example:user",
            subject_act: None,
            actor_sub: Some("did:example:agent"),
            client_id: Some("agent-client"),
            audience: Some("https://target.example"),
            scopes: &scopes,
            issued_at: 1_000,
            ttl_secs: 300,
            jti: "jti-123",
        });
        assert_eq!(claims["iss"], "did:webvh:example:gw");
        assert_eq!(claims["sub"], "did:example:user");
        assert_eq!(claims["aud"], "https://target.example");
        assert_eq!(claims["client_id"], "agent-client");
        assert_eq!(claims["scope"], "reports.read");
        assert_eq!(claims["iat"], 1_000);
        assert_eq!(claims["exp"], 1_300);
        assert_eq!(claims["jti"], "jti-123");
        assert_eq!(claims["act"], json!({ "sub": "did:example:agent" }));
    }

    #[test]
    fn build_claims_omits_optional_fields_when_absent() {
        let claims = build_access_token_claims(AccessTokenParams {
            issuer: "iss",
            subject: "sub",
            subject_act: None,
            actor_sub: None,
            client_id: None,
            audience: None,
            scopes: &[],
            issued_at: 5,
            ttl_secs: 10,
            jti: "j",
        });
        assert!(claims.get("aud").is_none());
        assert!(
            claims
                .get("client_id")
                .is_none()
        );
        assert!(claims.get("scope").is_none());
        assert!(claims.get("act").is_none(), "no actor and no subject act ⇒ no act claim");
    }

    #[test]
    fn validate_happy_path_defaults_requested_to_access_token() {
        let req = validate_token_exchange(&form(TOKEN_TYPE_JWT)).expect("valid");
        assert_eq!(req.subject_token_type, TokenType::Jwt);
        assert_eq!(req.requested_token_type, TokenType::AccessToken);
        assert!(req.actor_token.is_none());
    }

    #[test]
    fn validate_missing_subject_token_is_invalid_request() {
        let mut f = form(TOKEN_TYPE_JWT);
        f.subject_token = None;
        let err = validate_token_exchange(&f).unwrap_err();
        assert_eq!(err.error_code(), "invalid_request");
    }

    #[test]
    fn validate_unknown_subject_token_type_is_unsupported() {
        let f = form("urn:example:token-type:nope");
        let err = validate_token_exchange(&f).unwrap_err();
        assert_eq!(err.error_code(), "invalid_request");
        assert!(matches!(err, StsError::UnsupportedTokenType(_)));
    }

    #[test]
    fn validate_actor_token_without_type_is_rejected() {
        let mut f = form(TOKEN_TYPE_JWT);
        f.actor_token = Some("actor.jwt".to_string());
        let err = validate_token_exchange(&f).unwrap_err();
        assert_eq!(err.error_code(), "invalid_request");
    }

    #[test]
    fn validate_actor_type_without_token_is_rejected() {
        let mut f = form(TOKEN_TYPE_JWT);
        f.actor_token_type = Some(TOKEN_TYPE_JWT.to_string());
        let err = validate_token_exchange(&f).unwrap_err();
        assert_eq!(err.error_code(), "invalid_request");
    }

    #[test]
    fn validate_accepts_actor_pair_and_id_jag_request() {
        let mut f = form(TOKEN_TYPE_JWT);
        f.actor_token = Some("actor.jwt".to_string());
        f.actor_token_type = Some(TOKEN_TYPE_JWT.to_string());
        f.requested_token_type = Some(TOKEN_TYPE_ID_JAG.to_string());
        let req = validate_token_exchange(&f).expect("valid");
        assert_eq!(req.actor_token_type, Some(TokenType::Jwt));
        assert_eq!(req.requested_token_type, TokenType::IdJag);
    }

    #[test]
    fn validate_rejects_unissuable_requested_type() {
        let mut f = form(TOKEN_TYPE_JWT);
        f.requested_token_type = Some(TOKEN_TYPE_REFRESH_TOKEN.to_string());
        let err = validate_token_exchange(&f).unwrap_err();
        assert!(matches!(err, StsError::UnsupportedTokenType(_)));
    }

    #[test]
    fn resolve_scopes_unrestricted_when_allowlist_empty() {
        let requested = vec!["a".to_string(), "b".to_string()];
        assert_eq!(resolve_scopes(&requested, &[]).unwrap(), requested);
    }

    #[test]
    fn resolve_scopes_subset_allowed() {
        let requested = vec!["a".to_string()];
        let allowed = vec!["a".to_string(), "b".to_string()];
        assert_eq!(resolve_scopes(&requested, &allowed).unwrap(), requested);
    }

    #[test]
    fn resolve_scopes_superset_denied() {
        let requested = vec!["a".to_string(), "c".to_string()];
        let allowed = vec!["a".to_string(), "b".to_string()];
        let err = resolve_scopes(&requested, &allowed).unwrap_err();
        assert_eq!(err.error_code(), "invalid_scope");
    }

    #[test]
    fn ceiling_scopes_drops_scopes_outside_the_grant() {
        let requested = vec!["read".to_string(), "write".to_string(), "admin".to_string()];
        let ceiling = vec!["read".to_string(), "write".to_string()];
        assert_eq!(ceiling_scopes(&requested, &ceiling), vec!["read".to_string(), "write".to_string()]);
    }

    #[test]
    fn ceiling_scopes_empty_ceiling_passes_through() {
        let requested = vec!["read".to_string()];
        assert_eq!(ceiling_scopes(&requested, &[]), vec!["read".to_string()]);
    }

    #[test]
    fn ceiling_scopes_cannot_widen_beyond_grant() {
        // The grant authorized only `read`; a request for `read write` yields `read`.
        let requested = vec!["read".to_string(), "write".to_string()];
        let ceiling = vec!["read".to_string()];
        assert_eq!(ceiling_scopes(&requested, &ceiling), vec!["read".to_string()]);
    }

    #[test]
    fn effective_ttl_defaults_and_caps() {
        assert_eq!(effective_ttl(None, 300, 600), 300);
        assert_eq!(effective_ttl(Some(120), 300, 600), 120);
        assert_eq!(effective_ttl(Some(5_000), 300, 600), 600);
    }

    #[test]
    fn parse_scope_splits_on_whitespace() {
        assert_eq!(parse_scope("a  b\tc"), vec!["a", "b", "c"]);
        assert!(parse_scope("   ").is_empty());
    }
}
