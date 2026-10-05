//! Caller-context capture for Transit Point Workload Binding.
//!
//! GW1 sources caller context for the signed workload-binding VP from exactly
//! one place per Transit Point (see [`CallerContextSource`]):
//!
//! - **Transit token** — allowlisted caller-context fields captured on the
//!   Access Point path and carried forward in `X-Transit-Token`.
//! - **Bearer JWT** — claims lifted from the `Authorization: Bearer <jwt>`
//!   header presented on the Transit Point call itself.
//!
//! In both cases the operator-configured `caller_context_fields` allowlist is
//! the disclosure boundary: only configured top-level claim names are copied,
//! and their values are copied verbatim (any JSON value). A configured claim
//! that is missing from the source is simply omitted — never emitted as a null
//! or empty placeholder. GW2 policy decides whether a route strictly requires a
//! particular field.
//!
//! Signature verification of a bearer JWT is the source-auth layer's job; this
//! module operates on the token that layer has already accepted and only lifts
//! claims. It fails closed when the token is not a well-formed JWT.

use base64::Engine as _;
use serde_json::{Map, Value};

use crate::config::types::{CallerContextSource, WorkloadBindingConfig};
use crate::proxy::transit_token::TransitTokenClaims;

/// Caller context captured for a single Transit Point call, ready to feed the
/// workload-binding builder.
#[derive(Debug, Clone, PartialEq)]
pub struct CapturedCallerContext {
    /// Allowlisted caller-context fields, copied verbatim from the source.
    pub fields: Map<String, Value>,
    /// Stable correlation hash for the caller identity, when the source can
    /// supply one (the transit token carries `user_identity_hash`).
    pub user_hash: Option<String>,
    /// Where the caller context was sourced from.
    pub source: CallerContextSource,
}

/// Failure capturing caller context.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CallerContextCaptureError {
    /// An allowlist entry used nested-path (`a.b`) syntax, which is out of
    /// scope in v1 (top-level claim names only).
    #[error(
        "caller_context_fields entry '{name}' uses nested path syntax; only top-level claim names are supported in v1"
    )]
    NestedClaim { name: String },
    /// The `Authorization` header was not a usable `Bearer <jwt>` value.
    #[error("bearer JWT is malformed: {reason}")]
    MalformedBearerJwt { reason: String },
    /// `caller_source: did` was configured but the current request's
    /// authenticated identity is not [`AuthenticatedIdentity::DidAuth`]
    /// (either the request is anonymous or the surface uses a different
    /// source-auth method).
    #[error("caller_source=did requires a DID-authenticated caller; got {actual}")]
    NotDidAuthenticated { actual: &'static str },
}

/// Copy the allowlisted entries out of a source claim object. Missing entries
/// are omitted; values are copied as-is. Rejects nested-path allowlist entries.
fn select_allowlisted(
    source: &Map<String, Value>,
    allowlist: &[String],
) -> Result<Map<String, Value>, CallerContextCaptureError> {
    let mut out = Map::new();
    for name in allowlist {
        if name.contains('.') {
            return Err(CallerContextCaptureError::NestedClaim { name: name.clone() });
        }
        if let Some(value) = source.get(name) {
            out.insert(name.clone(), value.clone());
        }
    }
    Ok(out)
}

/// Capture caller context from an already-validated transit token.
pub fn capture_from_transit_token(
    claims: &TransitTokenClaims,
    allowlist: &[String],
) -> Result<CapturedCallerContext, CallerContextCaptureError> {
    let fields = select_allowlisted(&claims.caller_context_fields, allowlist)?;
    Ok(CapturedCallerContext {
        fields,
        user_hash: claims
            .user_identity_hash
            .clone(),
        source: CallerContextSource::TransitToken,
    })
}

/// Capture caller context from a Transit Point call's `Authorization` header.
///
/// `authorization` is the raw header value (e.g. `"Bearer eyJ..."`). The JWT's
/// claims are lifted without re-verifying its signature — verification is the
/// source-auth layer's responsibility. Fails closed when the value is not a
/// well-formed `Bearer <jwt>`.
pub fn capture_from_bearer_jwt(
    authorization: &str,
    allowlist: &[String],
) -> Result<CapturedCallerContext, CallerContextCaptureError> {
    let claims = decode_bearer_jwt_claims(authorization)?;
    let fields = select_allowlisted(&claims, allowlist)?;
    Ok(CapturedCallerContext {
        fields,
        user_hash: None,
        source: CallerContextSource::AuthorizationBearerJwt,
    })
}

/// Capture caller context from the current request's DID-authenticated
/// identity.
///
/// The caller identity is the DID resolved by
/// [`SourceAuthConfig::DidAuth`](crate::source_auth::models::SourceAuthConfig::DidAuth);
/// the emitted `user_hash` is `SHA256(did)` (hex) so it lines up with the
/// delegation-vault key used on every other auth method — see the caller-hash
/// normalisation in [`crate::proxy::handler`]. When `"did"` appears on the
/// operator-configured allowlist the DID is copied into `fields.did`; every
/// other allowlist entry is silently dropped (DID Auth carries no additional
/// claims). Rejects nested-path allowlist entries; fails closed when the
/// request is not DID-authenticated.
pub fn capture_from_did(
    identity: &crate::source_auth::AuthenticatedIdentity,
    allowlist: &[String],
) -> Result<CapturedCallerContext, CallerContextCaptureError> {
    use crate::source_auth::AuthenticatedIdentity as I;
    let did = match identity {
        I::DidAuth { did } => did,
        I::JwtBearer { .. } => return Err(CallerContextCaptureError::NotDidAuthenticated { actual: "jwt_bearer" }),
        I::ApiKey { .. } => return Err(CallerContextCaptureError::NotDidAuthenticated { actual: "api_key" }),
        I::Mtls { .. } => return Err(CallerContextCaptureError::NotDidAuthenticated { actual: "mtls" }),
    };
    let mut source_claims = Map::new();
    source_claims.insert("did".to_string(), Value::String(did.clone()));
    let fields = select_allowlisted(&source_claims, allowlist)?;
    use sha2::{Digest as _, Sha256};
    let user_hash = Some(format!("{:x}", Sha256::digest(did.as_bytes())));
    Ok(CapturedCallerContext {
        fields,
        user_hash,
        source: CallerContextSource::Did,
    })
}

/// Decode the (unverified) claim set from an `Authorization: Bearer <jwt>`
/// header value. Fails closed on anything that is not a three-segment JWT whose
/// payload segment is base64url-encoded JSON object.
fn decode_bearer_jwt_claims(authorization: &str) -> Result<Map<String, Value>, CallerContextCaptureError> {
    let malformed = |reason: &str| CallerContextCaptureError::MalformedBearerJwt { reason: reason.to_string() };

    let token = authorization
        .strip_prefix("Bearer ")
        .or_else(|| authorization.strip_prefix("bearer "))
        .unwrap_or(authorization)
        .trim();
    if token.is_empty() {
        return Err(malformed("empty token"));
    }

    let mut segments = token.split('.');
    let (_header, payload, signature) = match (segments.next(), segments.next(), segments.next()) {
        (Some(h), Some(p), Some(s)) => (h, p, s),
        _ => return Err(malformed("expected three dot-separated segments")),
    };
    if segments.next().is_some() || _header.is_empty() || payload.is_empty() || signature.is_empty() {
        return Err(malformed("expected exactly three non-empty segments"));
    }

    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .map_err(|_| malformed("payload is not valid base64url"))?;
    let value: Value = serde_json::from_slice(&decoded).map_err(|_| malformed("payload is not valid JSON"))?;
    match value {
        Value::Object(map) => Ok(map),
        _ => Err(malformed("payload is not a JSON object")),
    }
}

// ── Workload-binding credential-subject builder ───────────────────────────────

/// Caller-context assurance level carried in `credentialSubject.workloadBinding.caller`.
pub const ASSURANCE_GATEWAY_ATTESTED: &str = "gateway_attested";
/// Assurance level when a caller-supplied credential is chained into the VP.
pub const ASSURANCE_CALLER_CREDENTIAL_CHAINED: &str = "caller_credential_chained";

/// Optional inputs for [`build_workload_binding_subject`]. Everything is
/// optional so the builder can run on both the inbound response-injection path
/// and the outbound Transit Point path with whatever context is available.
#[derive(Debug, Default)]
pub struct WorkloadBindingInputs<'a> {
    /// Resolved managed agent identity fields (dot-notation keys). Filtered by
    /// `config.agent_fields` when that allowlist is non-empty.
    pub agent_identity_fields: Option<&'a std::collections::HashMap<String, Value>>,
    /// Captured caller context (from transit token or bearer JWT).
    pub caller: Option<&'a CapturedCallerContext>,
    /// A caller-supplied VC/VP to chain, embedded only when
    /// `config.chain_caller_credentials` is set.
    pub chained_caller_credential: Option<Value>,
    /// Gateway trace identifier.
    pub trace_id: Option<&'a str>,
    /// Structured intent object.
    pub intent: Option<Value>,
    /// Delegation-action object.
    pub delegation_actions: Option<Value>,
    /// Proxied target endpoint, embedded as `target` for provenance.
    pub target: Option<&'a str>,
    /// Policy decisions collected during the request.
    pub policy_decisions: Option<Value>,
}

/// Build the `credentialSubject.workloadBinding` object for a configured
/// Transit Point. Emits the nested caller-context vocabulary
/// (`agentIdentity`, `caller.{fields,user_hash,assurance,credential}`,
/// `traceId`, `intent`, `delegationAction`, `target`, `policyDecisions`,
/// `delegated`) while preserving the `AgentIdentityCredential` wire shape.
pub fn build_workload_binding_subject(
    config: &WorkloadBindingConfig,
    inputs: WorkloadBindingInputs<'_>,
) -> Value {
    let mut binding = Map::new();

    if let Some(fields) = inputs.agent_identity_fields {
        let expanded = if config.agent_fields.is_empty() {
            crate::config::expand_dot_notation(fields)
        } else {
            let filtered: std::collections::HashMap<String, Value> = fields
                .iter()
                .filter(|(k, _)| {
                    config
                        .agent_fields
                        .iter()
                        .any(|af| af.as_str() == k.as_str())
                })
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect();
            crate::config::expand_dot_notation(&filtered)
        };
        let agent_identity = expanded
            .get("agentIdentity")
            .cloned()
            .unwrap_or(expanded);
        binding.insert("agentIdentity".to_string(), agent_identity);
    }

    if let Some(caller) = inputs.caller {
        let mut caller_obj = Map::new();
        if !caller.fields.is_empty() {
            caller_obj.insert("fields".to_string(), Value::Object(caller.fields.clone()));
        }
        if let Some(hash) = &caller.user_hash {
            caller_obj.insert("user_hash".to_string(), Value::String(hash.clone()));
        }
        let source_tag = match caller.source {
            CallerContextSource::TransitToken => "transit_token",
            CallerContextSource::AuthorizationBearerJwt => "jwt_bearer",
            CallerContextSource::Did => "did_auth",
        };
        caller_obj.insert("identity_source".to_string(), Value::String(source_tag.to_string()));
        let chained = config.chain_caller_credentials
            && inputs
                .chained_caller_credential
                .is_some();
        caller_obj.insert(
            "assurance".to_string(),
            Value::String(
                if chained {
                    ASSURANCE_CALLER_CREDENTIAL_CHAINED
                } else {
                    ASSURANCE_GATEWAY_ATTESTED
                }
                .to_string(),
            ),
        );
        if chained {
            caller_obj.insert(
                "credential".to_string(),
                inputs
                    .chained_caller_credential
                    .clone()
                    .unwrap_or(Value::Null),
            );
        }
        binding.insert("caller".to_string(), Value::Object(caller_obj));
        binding.insert("delegated".to_string(), Value::Bool(true));
    }

    if let Some(tid) = inputs.trace_id {
        binding.insert("traceId".to_string(), Value::String(tid.to_string()));
    }
    if let Some(intent) = inputs.intent {
        binding.insert("intent".to_string(), intent);
    }
    if let Some(actions) = inputs.delegation_actions {
        binding.insert("delegationAction".to_string(), actions);
    }
    if let Some(decisions) = inputs.policy_decisions {
        binding.insert("policyDecisions".to_string(), decisions);
    }
    if let Some(target) = inputs.target
        && !target.is_empty()
    {
        binding.insert("target".to_string(), Value::String(target.to_string()));
    }

    Value::Object(binding)
}

/// Build a workload-binding object only when Workload Binding is configured and
/// enabled for the Transit Point. Returns `None` otherwise, so the caller falls
/// back to the legacy flat `identityFields` credential-subject shape.
pub fn maybe_build_workload_binding_subject(
    config: Option<&WorkloadBindingConfig>,
    inputs: WorkloadBindingInputs<'_>,
) -> Option<Value> {
    let config = config?;
    if !config.enabled {
        return None;
    }
    Some(build_workload_binding_subject(config, inputs))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_jwt(claims: Value) -> String {
        let b64 = |v: &[u8]| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(v);
        let header = b64(br#"{"alg":"HS256","typ":"JWT"}"#);
        let payload = b64(&serde_json::to_vec(&claims).unwrap());
        let signature = b64(b"signature");
        format!("{header}.{payload}.{signature}")
    }

    fn token_with_context(
        fields: Map<String, Value>,
        user_hash: Option<&str>,
    ) -> TransitTokenClaims {
        TransitTokenClaims {
            iss: "gw".to_string(),
            sub: None,
            surface_id: "surf-001".to_string(),
            iat: 0,
            exp: u64::MAX,
            jti: "jti".to_string(),
            identity_source: None,
            caller_dna_uai: None,
            user_identity_hash: user_hash.map(|s| s.to_string()),
            caller_context_fields: fields,
            allowed_transit_points: vec![],
            trace_id: None,
        }
    }

    // ── Transit token source ─────────────────────────────────────────────────

    #[test]
    fn transit_token_extracts_only_allowlisted_fields_with_user_hash() {
        let mut src = Map::new();
        src.insert("sub".to_string(), serde_json::json!("alice"));
        src.insert("email".to_string(), serde_json::json!("alice@example.test"));
        src.insert("secret".to_string(), serde_json::json!("should-not-leak"));
        let claims = token_with_context(src, Some("hash-1"));

        let captured = capture_from_transit_token(&claims, &["sub".to_string(), "email".to_string()]).unwrap();

        assert_eq!(captured.source, CallerContextSource::TransitToken);
        assert_eq!(captured.user_hash, Some("hash-1".to_string()));
        assert_eq!(captured.fields.len(), 2);
        assert_eq!(captured.fields["sub"], serde_json::json!("alice"));
        assert_eq!(captured.fields["email"], serde_json::json!("alice@example.test"));
        assert!(
            !captured
                .fields
                .contains_key("secret"),
            "unconfigured claims must not leak"
        );
    }

    #[test]
    fn transit_token_omits_missing_optional_claims() {
        let mut src = Map::new();
        src.insert("sub".to_string(), serde_json::json!("alice"));
        let claims = token_with_context(src, None);

        let captured = capture_from_transit_token(&claims, &["sub".to_string(), "email".to_string()]).unwrap();

        assert!(
            captured
                .fields
                .contains_key("sub")
        );
        assert!(
            !captured
                .fields
                .contains_key("email"),
            "a missing optional claim is absent, not a null/empty placeholder"
        );
    }

    #[test]
    fn transit_token_preserves_object_and_array_values_as_is() {
        let mut src = Map::new();
        src.insert("roles".to_string(), serde_json::json!(["admin", "ops"]));
        src.insert("org".to_string(), serde_json::json!({ "id": "acme", "tier": 3 }));
        let claims = token_with_context(src, None);

        let captured = capture_from_transit_token(&claims, &["roles".to_string(), "org".to_string()]).unwrap();

        assert_eq!(captured.fields["roles"], serde_json::json!(["admin", "ops"]));
        assert_eq!(captured.fields["org"], serde_json::json!({ "id": "acme", "tier": 3 }));
    }

    #[test]
    fn transit_token_rejects_nested_path_allowlist() {
        let claims = token_with_context(Map::new(), None);
        let err = capture_from_transit_token(&claims, &["profile.email".to_string()]).unwrap_err();
        assert_eq!(err, CallerContextCaptureError::NestedClaim { name: "profile.email".into() });
    }

    // ── Bearer JWT source ────────────────────────────────────────────────────

    #[test]
    fn bearer_jwt_extracts_selected_claims_and_ignores_the_rest() {
        let jwt = make_jwt(serde_json::json!({
            "sub": "alice-subject",
            "iss": "https://idp.example.test",
            "email": "alice@example.test",
            "unrelated": "ignored"
        }));
        let auth = format!("Bearer {jwt}");

        let captured = capture_from_bearer_jwt(&auth, &["sub".to_string(), "iss".to_string()]).unwrap();

        assert_eq!(captured.source, CallerContextSource::AuthorizationBearerJwt);
        assert_eq!(captured.fields.len(), 2);
        assert_eq!(captured.fields["sub"], serde_json::json!("alice-subject"));
        assert_eq!(captured.fields["iss"], serde_json::json!("https://idp.example.test"));
        assert!(
            !captured
                .fields
                .contains_key("email")
        );
        assert!(
            !captured
                .fields
                .contains_key("unrelated")
        );
    }

    #[test]
    fn bearer_jwt_preserves_any_json_value() {
        let jwt = make_jwt(serde_json::json!({
            "roles": ["a", "b"],
            "meta": { "n": 1 },
            "count": 7
        }));
        let auth = format!("Bearer {jwt}");

        let captured =
            capture_from_bearer_jwt(&auth, &["roles".to_string(), "meta".to_string(), "count".to_string()]).unwrap();

        assert_eq!(captured.fields["roles"], serde_json::json!(["a", "b"]));
        assert_eq!(captured.fields["meta"], serde_json::json!({ "n": 1 }));
        assert_eq!(captured.fields["count"], serde_json::json!(7));
    }

    #[test]
    fn bearer_jwt_rejects_nested_path_allowlist() {
        let jwt = make_jwt(serde_json::json!({ "sub": "alice" }));
        let auth = format!("Bearer {jwt}");
        let err = capture_from_bearer_jwt(&auth, &["a.b".to_string()]).unwrap_err();
        assert_eq!(err, CallerContextCaptureError::NestedClaim { name: "a.b".into() });
    }

    #[test]
    fn bearer_jwt_fails_closed_on_malformed_token() {
        // Not three segments.
        assert!(matches!(
            capture_from_bearer_jwt("Bearer not-a-jwt", &["sub".to_string()]),
            Err(CallerContextCaptureError::MalformedBearerJwt { .. })
        ));
        // Payload is not base64url JSON.
        assert!(matches!(
            capture_from_bearer_jwt("Bearer aaa.!!!.ccc", &["sub".to_string()]),
            Err(CallerContextCaptureError::MalformedBearerJwt { .. })
        ));
        // Empty token.
        assert!(matches!(
            capture_from_bearer_jwt("Bearer ", &["sub".to_string()]),
            Err(CallerContextCaptureError::MalformedBearerJwt { .. })
        ));
    }

    #[test]
    fn bearer_jwt_payload_must_be_a_json_object() {
        let b64 = |v: &[u8]| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(v);
        let jwt = format!("{}.{}.{}", b64(b"{}"), b64(b"[1,2,3]"), b64(b"sig"));
        let auth = format!("Bearer {jwt}");
        assert!(matches!(
            capture_from_bearer_jwt(&auth, &["sub".to_string()]),
            Err(CallerContextCaptureError::MalformedBearerJwt { .. })
        ));
    }

    // ── DID source ───────────────────────────────────────────────────────────

    #[test]
    fn did_source_populates_sha256_user_hash() {
        let identity = crate::source_auth::AuthenticatedIdentity::DidAuth {
            did: "did:example:alice".to_string(),
        };
        let captured = capture_from_did(&identity, &[]).unwrap();
        assert_eq!(captured.source, CallerContextSource::Did);
        assert!(captured.fields.is_empty());
        use sha2::{Digest as _, Sha256};
        let expected_hash = format!("{:x}", Sha256::digest(b"did:example:alice"));
        assert_eq!(captured.user_hash, Some(expected_hash));
    }

    #[test]
    fn did_source_emits_did_field_when_allowlisted() {
        let identity = crate::source_auth::AuthenticatedIdentity::DidAuth {
            did: "did:example:bob".to_string(),
        };
        let captured = capture_from_did(&identity, &["did".to_string(), "sub".to_string()]).unwrap();
        assert_eq!(captured.fields.len(), 1);
        assert_eq!(captured.fields["did"], serde_json::json!("did:example:bob"));
    }

    #[test]
    fn did_source_rejects_nested_path_allowlist() {
        let identity = crate::source_auth::AuthenticatedIdentity::DidAuth {
            did: "did:example:carol".to_string(),
        };
        let err = capture_from_did(&identity, &["a.b".to_string()]).unwrap_err();
        assert_eq!(err, CallerContextCaptureError::NestedClaim { name: "a.b".into() });
    }

    #[test]
    fn did_source_fails_closed_on_non_did_identity() {
        let jwt = crate::source_auth::AuthenticatedIdentity::JwtBearer {
            subject: "alice".to_string(),
            claims: serde_json::json!({}),
        };
        let err = capture_from_did(&jwt, &[]).unwrap_err();
        assert_eq!(err, CallerContextCaptureError::NotDidAuthenticated { actual: "jwt_bearer" });

        let api = crate::source_auth::AuthenticatedIdentity::ApiKey { key_name: "k".into() };
        assert_eq!(
            capture_from_did(&api, &[]).unwrap_err(),
            CallerContextCaptureError::NotDidAuthenticated { actual: "api_key" }
        );
    }

    // ── Builder ──────────────────────────────────────────────────────────────

    fn enabled_config() -> WorkloadBindingConfig {
        WorkloadBindingConfig {
            enabled: true,
            caller_source: CallerContextSource::TransitToken,
            caller_context_fields: vec!["sub".to_string()],
            ..Default::default()
        }
    }

    fn caller(
        fields: Map<String, Value>,
        user_hash: Option<&str>,
    ) -> CapturedCallerContext {
        CapturedCallerContext {
            fields,
            user_hash: user_hash.map(|s| s.to_string()),
            source: CallerContextSource::TransitToken,
        }
    }

    #[test]
    fn builder_builds_agent_identity_from_fields() {
        let mut agent = std::collections::HashMap::new();
        agent.insert("agentIdentity.model".to_string(), serde_json::json!("gpt-4"));
        let config = enabled_config();
        let out = build_workload_binding_subject(
            &config,
            WorkloadBindingInputs {
                agent_identity_fields: Some(&agent),
                ..Default::default()
            },
        );
        assert_eq!(out["agentIdentity"]["model"], serde_json::json!("gpt-4"));
    }

    #[test]
    fn builder_builds_caller_fields_user_hash_and_assurance() {
        let mut fields = Map::new();
        fields.insert("sub".to_string(), serde_json::json!("alice"));
        let config = enabled_config();
        let out = build_workload_binding_subject(
            &config,
            WorkloadBindingInputs {
                caller: Some(&caller(fields, Some("hash-1"))),
                ..Default::default()
            },
        );
        assert_eq!(out["caller"]["fields"]["sub"], serde_json::json!("alice"));
        assert_eq!(out["caller"]["user_hash"], serde_json::json!("hash-1"));
        assert_eq!(out["caller"]["identity_source"], serde_json::json!("transit_token"));
        assert_eq!(out["caller"]["assurance"], serde_json::json!("gateway_attested"));
        assert_eq!(out["delegated"], serde_json::json!(true));
    }

    #[test]
    fn builder_preserves_object_and_array_caller_values() {
        let mut fields = Map::new();
        fields.insert("roles".to_string(), serde_json::json!(["admin", "ops"]));
        fields.insert("org".to_string(), serde_json::json!({ "id": "acme" }));
        let config = enabled_config();
        let out = build_workload_binding_subject(
            &config,
            WorkloadBindingInputs {
                caller: Some(&caller(fields, None)),
                ..Default::default()
            },
        );
        assert_eq!(out["caller"]["fields"]["roles"], serde_json::json!(["admin", "ops"]));
        assert_eq!(out["caller"]["fields"]["org"], serde_json::json!({ "id": "acme" }));
    }

    #[test]
    fn builder_adds_optional_binding_fields_when_available() {
        let config = enabled_config();
        let out = build_workload_binding_subject(
            &config,
            WorkloadBindingInputs {
                caller: Some(&caller(Map::new(), None)),
                trace_id: Some("trace-123"),
                intent: Some(serde_json::json!({ "action": "schedule" })),
                delegation_actions: Some(serde_json::json!(["read"])),
                target: Some("fabric://gw2/alpha"),
                policy_decisions: Some(serde_json::json!([{ "scope": "surface", "allow": true }])),
                ..Default::default()
            },
        );
        assert_eq!(out["traceId"], serde_json::json!("trace-123"));
        assert_eq!(out["intent"], serde_json::json!({ "action": "schedule" }));
        assert_eq!(out["delegationAction"], serde_json::json!(["read"]));
        assert_eq!(out["target"], serde_json::json!("fabric://gw2/alpha"));
        assert_eq!(out["policyDecisions"], serde_json::json!([{ "scope": "surface", "allow": true }]));
    }

    #[test]
    fn builder_omits_delegated_when_no_caller() {
        let config = enabled_config();
        let out = build_workload_binding_subject(&config, WorkloadBindingInputs::default());
        assert!(out.get("caller").is_none());
        assert!(out.get("delegated").is_none(), "delegated must be absent without caller context");
    }

    #[test]
    fn builder_includes_chained_credential_only_when_configured() {
        let mut fields = Map::new();
        fields.insert("sub".to_string(), serde_json::json!("alice"));
        let cred = serde_json::json!({ "type": "VerifiablePresentation" });

        // Not configured to chain: assurance stays gateway_attested, no credential.
        let config = enabled_config();
        let out = build_workload_binding_subject(
            &config,
            WorkloadBindingInputs {
                caller: Some(&caller(fields.clone(), None)),
                chained_caller_credential: Some(cred.clone()),
                ..Default::default()
            },
        );
        assert_eq!(out["caller"]["assurance"], serde_json::json!("gateway_attested"));
        assert!(
            out["caller"]
                .get("credential")
                .is_none()
        );

        // Configured to chain and a credential provided: assurance upgrades.
        let chaining_config = WorkloadBindingConfig {
            chain_caller_credentials: true,
            ..enabled_config()
        };
        let out2 = build_workload_binding_subject(
            &chaining_config,
            WorkloadBindingInputs {
                caller: Some(&caller(fields, None)),
                chained_caller_credential: Some(cred.clone()),
                ..Default::default()
            },
        );
        assert_eq!(out2["caller"]["assurance"], serde_json::json!("caller_credential_chained"));
        assert_eq!(out2["caller"]["credential"], cred);
    }

    #[test]
    fn maybe_build_returns_none_when_not_configured_or_disabled() {
        // Not configured at all.
        assert!(maybe_build_workload_binding_subject(None, WorkloadBindingInputs::default()).is_none());
        // Configured but disabled.
        let disabled = WorkloadBindingConfig::default();
        assert!(maybe_build_workload_binding_subject(Some(&disabled), WorkloadBindingInputs::default()).is_none());
        // Enabled → Some.
        let config = enabled_config();
        assert!(maybe_build_workload_binding_subject(Some(&config), WorkloadBindingInputs::default()).is_some());
    }
}
