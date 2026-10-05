use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::jwt_bearer::{JwtBearerVerifier, models::JwtVerificationStrategy};
use crate::mcp::continuations::{ContinuationError, protected::ConsentTicket};
use crate::sts::mcp_profile::McpIssuerProfile;

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifiedConsentIdentity {
    principal: String,
    provider_digest: [u8; 32],
    strategy_digest: [u8; 32],
}

impl VerifiedConsentIdentity {
    pub fn matches(
        &self,
        principal: &str,
        provider_digest: [u8; 32],
        strategy_digest: [u8; 32],
    ) -> bool {
        self.principal == principal
            && self.provider_digest == provider_digest
            && self.strategy_digest == strategy_digest
    }

    /// Deliberately weaker than [`Self::matches`]: it binds only the consenting
    /// `(issuer, subject)`. Legacy delegation has no provider/strategy snapshot
    /// to compare, so this is what the legacy vault read can check.
    pub fn matches_principal(
        &self,
        principal: &str,
    ) -> bool {
        self.principal == principal
    }
}

/// Principal digest for an authenticated caller, in the same shape
/// [`verify_id_token`] binds into a consent record.
pub fn principal_for_claims(
    profile: &McpIssuerProfile,
    claims: &Value,
) -> Option<String> {
    let subject = profile
        .bound_subject(claims)
        .ok()?;
    let principal = serde_json_canonicalizer::to_vec(&(&profile.issuer, &subject)).ok()?;
    Some(hex::encode(Sha256::digest(principal)))
}

pub fn nonce(ticket: &ConsentTicket) -> String {
    format!("mcp-consent-{}", ticket.id)
}

pub async fn verify_id_token(
    verifier: &JwtBearerVerifier,
    strategy: &JwtVerificationStrategy,
    profile: &McpIssuerProfile,
    ticket: &ConsentTicket,
    client_id: &str,
    token: &str,
    now: u64,
) -> Result<VerifiedConsentIdentity, ContinuationError> {
    ticket.validate(true, now)?;
    if token.is_empty() || token.len() > 32 * 1024 || client_id.is_empty() || client_id.len() > 4096 {
        return Err(ContinuationError::InvalidInputResponse);
    }
    let header = jsonwebtoken::decode_header(token).map_err(|_| ContinuationError::InvalidState)?;
    if header
        .typ
        .as_deref()
        .is_some_and(|typ| typ != "JWT")
    {
        return Err(ContinuationError::InvalidState);
    }
    let claims = verifier
        .validate(token, strategy, &[client_id.to_string()])
        .await
        .map_err(|_| ContinuationError::InvalidState)?;
    profile
        .validate_subject(&claims, now)
        .map_err(|_| ContinuationError::InvalidState)?;
    if claims
        .get("nonce")
        .and_then(Value::as_str)
        != Some(nonce(ticket).as_str())
        || claims
            .get("iat")
            .and_then(Value::as_u64)
            .is_none_or(|issued| issued > now.saturating_add(120) || issued.saturating_add(120) < ticket.issued_at)
    {
        return Err(ContinuationError::InvalidState);
    }
    let multiple_audiences = match claims.get("aud") {
        Some(Value::String(audience)) => {
            if audience != client_id {
                return Err(ContinuationError::InvalidState);
            }
            false
        }
        Some(Value::Array(audiences)) if !audiences.is_empty() => {
            if audiences.iter().any(|value| {
                value
                    .as_str()
                    .is_none_or(str::is_empty)
            }) || !audiences
                .iter()
                .any(|value| value.as_str() == Some(client_id))
            {
                return Err(ContinuationError::InvalidState);
            }
            audiences.len() > 1
        }
        _ => return Err(ContinuationError::InvalidState),
    };
    if (multiple_audiences || claims.get("azp").is_some())
        && claims
            .get("azp")
            .and_then(Value::as_str)
            != Some(client_id)
    {
        return Err(ContinuationError::InvalidState);
    }
    let subject = profile
        .bound_subject(&claims)
        .map_err(|_| ContinuationError::BindingMismatch)?;
    let principal =
        serde_json_canonicalizer::to_vec(&(&profile.issuer, &subject)).map_err(|_| ContinuationError::InvalidRecord)?;
    if hex::encode(Sha256::digest(principal)) != ticket.binding.principal
        || hex::encode(Sha256::digest(subject.as_bytes()))
            != ticket
                .binding
                .user_identity_hash
    {
        return Err(ContinuationError::BindingMismatch);
    }
    Ok(VerifiedConsentIdentity {
        principal: ticket
            .binding
            .principal
            .clone(),
        provider_digest: ticket.provider_digest,
        strategy_digest: ticket.identity_strategy_digest,
    })
}

#[cfg(test)]
mod tests {
    use base64::Engine as _;
    use ed25519_dalek::Signer as _;
    use serde_json::json;

    use super::*;

    #[tokio::test]
    async fn provider_id_token_requires_bound_nonce_audience_issuer_and_subject() {
        let signing = ed25519_dalek::SigningKey::from_bytes(&[9; 32]);
        let encoding = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let jwks = json!({"keys": [{"kty": "OKP", "crv": "Ed25519", "alg": "EdDSA", "kid": "key-1", "x": encoding.encode(signing.verifying_key().as_bytes())}]});
        let strategy = crate::sts::handlers::gateway_self_trust_strategy("https://identity.example/", &jwks).unwrap();
        let verifier = JwtBearerVerifier::new(std::sync::Arc::new(crate::jwt_bearer::JwksClient::new()));
        let profile = McpIssuerProfile {
            issuer: "https://gateway.example/oauth2/mcp".into(),
        };
        let now = chrono::Utc::now().timestamp() as u64;
        let subject = profile
            .bound_subject(&json!({"iss": strategy.expected_issuer, "sub": "alice"}))
            .unwrap();
        let ticket: ConsentTicket = serde_json::from_value(json!({
            "id": uuid::Uuid::new_v4(), "continuation_id": uuid::Uuid::new_v4(), "issued_at": now, "expires_at": now + 300,
            "provider_digest": ([3; 32]), "surface_digest": ([4; 32]), "identity_strategy_digest": ([5; 32]),
            "callback_url": "https://gateway.example/mcp-consent/callback/provider", "code_verifier": "v".repeat(43),
            "binding": {"deployment": "deployment", "principal": hex::encode(Sha256::digest(serde_json_canonicalizer::to_vec(&(&profile.issuer, &subject)).unwrap())),
                "agent_did": "did:web:agent", "user_identity_hash": hex::encode(Sha256::digest(subject.as_bytes())),
                "authorization_digest": ([1; 32]), "tenant_id": null, "surface_id": "surface", "variant_id": null, "route": {"kind": "access_point"},
                "resource": "https://gateway.example/mcp", "provider_id": "provider", "scopes": ["openid"], "method": "tools/call", "arguments_digest": ([2; 32])}
        })).unwrap();
        let claims = json!({"iss": strategy.expected_issuer, "sub": "alice", "aud": "provider-client", "exp": now + 300, "iat": now, "nonce": nonce(&ticket)});
        let sign = |claims: &Value| {
            let header = encoding.encode(br#"{"alg":"EdDSA","typ":"JWT","kid":"key-1"}"#);
            let body = encoding.encode(serde_json::to_vec(claims).unwrap());
            let input = format!("{header}.{body}");
            format!(
                "{input}.{}",
                encoding.encode(
                    signing
                        .sign(input.as_bytes())
                        .to_bytes()
                )
            )
        };
        let verified = verify_id_token(&verifier, &strategy, &profile, &ticket, "provider-client", &sign(&claims), now)
            .await
            .unwrap();
        assert!(verified.matches(&ticket.binding.principal, ticket.provider_digest, ticket.identity_strategy_digest));
        assert!(!verified.matches("another-principal", ticket.provider_digest, ticket.identity_strategy_digest));
        assert!(!verified.matches(&ticket.binding.principal, [9; 32], ticket.identity_strategy_digest));
        assert!(!verified.matches(&ticket.binding.principal, ticket.provider_digest, [9; 32]));
        for (field, value) in [
            ("nonce", json!("different")),
            ("aud", json!("different-client")),
            ("iss", json!("https://different.example/")),
            ("sub", json!("bob")),
            ("exp", json!(now)),
            ("iat", json!(now + 121)),
            ("aud", json!(["provider-client", "another-client"])),
            ("azp", json!("different-client")),
        ] {
            let mut changed = claims.clone();
            changed[field] = value;
            assert!(
                verify_id_token(&verifier, &strategy, &profile, &ticket, "provider-client", &sign(&changed), now)
                    .await
                    .is_err(),
                "{field}"
            );
        }
        let mut multiple = claims.clone();
        multiple["aud"] = json!(["provider-client", "another-client"]);
        multiple["azp"] = json!("provider-client");
        assert_eq!(
            verify_id_token(&verifier, &strategy, &profile, &ticket, "provider-client", &sign(&multiple), now).await,
            Ok(verified)
        );
        let forged = format!(
            "{}.bad",
            sign(&claims)
                .rsplit_once('.')
                .unwrap()
                .0
        );
        assert!(
            verify_id_token(&verifier, &strategy, &profile, &ticket, "provider-client", &forged, now)
                .await
                .is_err()
        );
    }
}
