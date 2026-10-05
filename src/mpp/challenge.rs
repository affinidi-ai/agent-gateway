//! MPP challenge generation with HMAC-SHA256 binding
//!
//! Implements stateless challenge binding per draft-httpauth-payment-00 Section 5.1.2.1.1.
//! The challenge `id` is computed as HMAC-SHA256 over pipe-delimited positional slots.

use base64::Engine;
use hmac::{Hmac, Mac};
use sha2::Sha256;

use super::types::{MppChallenge, MppConfig, MppPaymentMethod, MppPaymentRequest};

type HmacSha256 = Hmac<Sha256>;

/// Base64url encoding without padding (per RFC 4648 Section 5)
pub fn base64url_encode_nopad(data: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data)
}

/// Base64url decoding without padding
pub fn base64url_decode_nopad(s: &str) -> Result<Vec<u8>, base64::DecodeError> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(s)
}

/// Resolve a potentially environment-variable-referenced secret key.
/// If the value starts with "$", treat it as an env var name.
fn resolve_secret_key(key: &str) -> Vec<u8> {
    let raw = if let Some(var_name) = key.strip_prefix('$') {
        std::env::var(var_name).unwrap_or_default()
    } else {
        key.to_string()
    };
    // Decode from base64 (the secret_key config field is base64-encoded)
    base64::engine::general_purpose::STANDARD
        .decode(&raw)
        .unwrap_or_else(|_| raw.into_bytes())
}

/// Compute the challenge `id` as HMAC-SHA256 over positional slots.
///
/// Input slots (always 7, absent optionals use empty string):
///   0: realm
///   1: method
///   2: intent
///   3: request (base64url-encoded JCS JSON)
///   4: expires (or "")
///   5: digest (or "")
///   6: opaque (base64url-encoded JCS JSON, or "")
///
/// Joined with "|" delimiter, then HMAC-SHA256 → base64url no-pad.
pub fn compute_challenge_id(
    secret: &[u8],
    realm: &str,
    method: &str,
    intent: &str,
    request_b64url: &str,
    expires: Option<&str>,
    digest: Option<&str>,
    opaque: Option<&str>,
) -> Result<String, String> {
    let input = format!(
        "{}|{}|{}|{}|{}|{}|{}",
        realm,
        method,
        intent,
        request_b64url,
        expires.unwrap_or(""),
        digest.unwrap_or(""),
        opaque.unwrap_or(""),
    );

    let mut mac = HmacSha256::new_from_slice(secret).map_err(|e| format!("HMAC key error: {}", e))?;
    mac.update(input.as_bytes());
    let result = mac.finalize().into_bytes();

    Ok(base64url_encode_nopad(&result))
}

/// Verify that a challenge id matches the expected HMAC binding.
pub fn verify_challenge_id(
    secret: &[u8],
    challenge_id: &str,
    realm: &str,
    method: &str,
    intent: &str,
    request_b64url: &str,
    expires: Option<&str>,
    digest: Option<&str>,
    opaque: Option<&str>,
) -> Result<bool, String> {
    let expected = compute_challenge_id(secret, realm, method, intent, request_b64url, expires, digest, opaque)?;
    // Constant-time comparison to avoid timing attacks
    Ok(constant_time_eq(challenge_id.as_bytes(), expected.as_bytes()))
}

/// Constant-time byte comparison
fn constant_time_eq(
    a: &[u8],
    b: &[u8],
) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Encode the payment request as base64url JCS JSON.
///
/// Per the spec, the `request` parameter MUST be serialized using JSON
/// Canonicalization Scheme (JCS) per RFC 8785 before base64url encoding.
fn encode_payment_request(payment_request: &MppPaymentRequest) -> Result<String, String> {
    let jcs_bytes = serde_jcs::to_vec(payment_request).map_err(|e| format!("JCS serialization error: {}", e))?;
    Ok(base64url_encode_nopad(&jcs_bytes))
}

/// Generate all MPP challenges for a given config.
///
/// Returns one `MppChallenge` per configured payment method, each with a
/// unique HMAC-bound `id`.
pub fn generate_challenges(
    config: &MppConfig,
    resource_url: &str,
) -> Result<Vec<MppChallenge>, String> {
    let secret = resolve_secret_key(&config.secret_key);
    let now = chrono::Utc::now();
    let expires = now + chrono::Duration::seconds(config.challenge_ttl_seconds as i64);
    let expires_str = expires.to_rfc3339_opts(chrono::SecondsFormat::Secs, true);

    let mut challenges = Vec::with_capacity(config.payment_methods.len());

    for pm in &config.payment_methods {
        let challenge = generate_single_challenge(&secret, config, pm, resource_url, &expires_str)?;
        challenges.push(challenge);
    }

    Ok(challenges)
}

/// Generate a single challenge for one payment method.
fn generate_single_challenge(
    secret: &[u8],
    config: &MppConfig,
    pm: &MppPaymentMethod,
    _resource_url: &str,
    expires_str: &str,
) -> Result<MppChallenge, String> {
    let payment_request = MppPaymentRequest {
        amount: pm.amount.clone(),
        currency: pm.currency.clone(),
        recipient: pm.recipient.clone(),
        extra: pm
            .network
            .as_ref()
            .map(|n| serde_json::json!({"network": n})),
    };

    let request_b64url = encode_payment_request(&payment_request)?;

    // A per-issue random nonce so two challenges for the same method/amount are
    // never identical or guessable; the client echoes it back in the credential.
    let opaque = uuid::Uuid::new_v4().to_string();

    let id = compute_challenge_id(
        secret,
        &config.realm,
        &pm.method,
        &pm.intent,
        &request_b64url,
        Some(expires_str),
        None, // digest
        Some(&opaque),
    )?;

    Ok(MppChallenge {
        id,
        realm: config.realm.clone(),
        method: pm.method.clone(),
        intent: pm.intent.clone(),
        request: request_b64url,
        expires: Some(expires_str.to_string()),
        digest: None,
        description: None,
        opaque: Some(opaque),
    })
}

/// Format an `MppChallenge` as a `WWW-Authenticate: Payment` header value.
///
/// Per the spec, the challenge uses auth-param syntax:
/// ```text
/// Payment id="...", realm="...", method="...", intent="...", request="...", expires="..."
/// ```
pub fn format_www_authenticate(challenge: &MppChallenge) -> String {
    let mut parts = vec![
        format!("Payment id=\"{}\"", challenge.id),
        format!("realm=\"{}\"", challenge.realm),
        format!("method=\"{}\"", challenge.method),
        format!("intent=\"{}\"", challenge.intent),
        format!("request=\"{}\"", challenge.request),
    ];

    if let Some(ref expires) = challenge.expires {
        parts.push(format!("expires=\"{}\"", expires));
    }
    if let Some(ref digest) = challenge.digest {
        parts.push(format!("digest=\"{}\"", digest));
    }
    if let Some(ref description) = challenge.description {
        parts.push(format!("description=\"{}\"", description));
    }
    if let Some(ref opaque) = challenge.opaque {
        parts.push(format!("opaque=\"{}\"", opaque));
    }

    parts.join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mpp::types::MppVerificationMode;

    #[test]
    fn test_base64url_encode_decode_roundtrip() {
        let data = b"hello world";
        let encoded = base64url_encode_nopad(data);
        assert!(!encoded.contains('='), "should not have padding");
        assert!(!encoded.contains('+'), "should use URL-safe alphabet");
        assert!(!encoded.contains('/'), "should use URL-safe alphabet");
        let decoded = base64url_decode_nopad(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_compute_challenge_id_deterministic() {
        let secret = b"test-secret";
        let id1 = compute_challenge_id(
            secret,
            "api.example.com",
            "tempo",
            "charge",
            "eyJhbW91bnQiOiIxMDAifQ",
            Some("2026-01-15T12:05:00Z"),
            None,
            None,
        )
        .unwrap();
        let id2 = compute_challenge_id(
            secret,
            "api.example.com",
            "tempo",
            "charge",
            "eyJhbW91bnQiOiIxMDAifQ",
            Some("2026-01-15T12:05:00Z"),
            None,
            None,
        )
        .unwrap();
        assert_eq!(id1, id2, "Same inputs should produce same id");
    }

    #[test]
    fn test_compute_challenge_id_different_inputs() {
        let secret = b"test-secret";
        let id1 = compute_challenge_id(
            secret,
            "api.example.com",
            "tempo",
            "charge",
            "eyJhbW91bnQiOiIxMDAifQ",
            Some("2026-01-15T12:05:00Z"),
            None,
            None,
        )
        .unwrap();
        let id2 = compute_challenge_id(
            secret,
            "api.other.com",
            "tempo",
            "charge",
            "eyJhbW91bnQiOiIxMDAifQ",
            Some("2026-01-15T12:05:00Z"),
            None,
            None,
        )
        .unwrap();
        assert_ne!(id1, id2, "Different realm should produce different id");
    }

    #[test]
    fn test_verify_challenge_id_success() {
        let secret = b"test-secret";
        let id = compute_challenge_id(
            secret,
            "api.example.com",
            "tempo",
            "charge",
            "req_b64",
            Some("2026-01-15T12:05:00Z"),
            None,
            None,
        )
        .unwrap();
        assert!(
            verify_challenge_id(
                secret,
                &id,
                "api.example.com",
                "tempo",
                "charge",
                "req_b64",
                Some("2026-01-15T12:05:00Z"),
                None,
                None,
            )
            .unwrap()
        );
    }

    #[test]
    fn test_verify_challenge_id_tampered() {
        let secret = b"test-secret";
        let id = compute_challenge_id(
            secret,
            "api.example.com",
            "tempo",
            "charge",
            "req_b64",
            Some("2026-01-15T12:05:00Z"),
            None,
            None,
        )
        .unwrap();
        // Try verifying with a different request
        assert!(
            !verify_challenge_id(
                secret,
                &id,
                "api.example.com",
                "tempo",
                "charge",
                "TAMPERED",
                Some("2026-01-15T12:05:00Z"),
                None,
                None,
            )
            .unwrap()
        );
    }

    #[test]
    fn test_format_www_authenticate() {
        let challenge = MppChallenge {
            id: "abc123".to_string(),
            realm: "api.example.com".to_string(),
            method: "tempo".to_string(),
            intent: "charge".to_string(),
            request: "eyJ0ZXN0IjoxfQ".to_string(),
            expires: Some("2026-01-15T12:05:00Z".to_string()),
            digest: None,
            description: None,
            opaque: None,
        };

        let header = format_www_authenticate(&challenge);
        assert!(header.starts_with("Payment id=\"abc123\""));
        assert!(header.contains("realm=\"api.example.com\""));
        assert!(header.contains("method=\"tempo\""));
        assert!(header.contains("intent=\"charge\""));
        assert!(header.contains("request=\"eyJ0ZXN0IjoxfQ\""));
        assert!(header.contains("expires=\"2026-01-15T12:05:00Z\""));
    }

    #[test]
    fn test_generate_challenges() {
        let config = MppConfig {
            enabled: true,
            realm: "test.example.com".to_string(),
            secret_key: base64::engine::general_purpose::STANDARD.encode(b"test-secret-key-32bytes-long!!!!"),
            stripe_secret_key: None,
            payment_methods: vec![MppPaymentMethod {
                method: "tempo".to_string(),
                intent: "charge".to_string(),
                currency: "0x20c0".to_string(),
                recipient: "0xrecipient".to_string(),
                amount: "0.01".to_string(),
                network: Some("tempo".to_string()),
            }],
            challenge_ttl_seconds: 300,
            mcp_payment_triggers: None,
            a2a_method_filters: None,
            verification_timeout_ms: 10000,
            crypto_verification_mode: MppVerificationMode::default(),
            rpc_endpoints: std::collections::HashMap::new(),
            min_confirmations: 0,
        };

        let challenges = generate_challenges(&config, "/api/resource").unwrap();
        assert_eq!(challenges.len(), 1);

        let c = &challenges[0];
        assert_eq!(c.realm, "test.example.com");
        assert_eq!(c.method, "tempo");
        assert_eq!(c.intent, "charge");
        assert!(!c.id.is_empty());
        assert!(!c.request.is_empty());
        assert!(c.expires.is_some());

        // Verify the challenge id is valid
        let secret = base64::engine::general_purpose::STANDARD
            .decode(base64::engine::general_purpose::STANDARD.encode(b"test-secret-key-32bytes-long!!!!"))
            .unwrap();
        assert!(
            verify_challenge_id(
                &secret,
                &c.id,
                &c.realm,
                &c.method,
                &c.intent,
                &c.request,
                c.expires.as_deref(),
                c.digest.as_deref(),
                c.opaque.as_deref(),
            )
            .unwrap()
        );
    }

    #[test]
    fn test_generate_challenges_unique_opaque_per_issue() {
        let config = MppConfig {
            enabled: true,
            realm: "test.example.com".to_string(),
            secret_key: base64::engine::general_purpose::STANDARD.encode(b"test-secret-key-32bytes-long!!!!"),
            stripe_secret_key: None,
            payment_methods: vec![MppPaymentMethod {
                method: "tempo".to_string(),
                intent: "charge".to_string(),
                currency: "0x20c0".to_string(),
                recipient: "0xrecipient".to_string(),
                amount: "0.01".to_string(),
                network: Some("tempo".to_string()),
            }],
            challenge_ttl_seconds: 300,
            mcp_payment_triggers: None,
            a2a_method_filters: None,
            verification_timeout_ms: 10000,
            crypto_verification_mode: MppVerificationMode::default(),
            rpc_endpoints: std::collections::HashMap::new(),
            min_confirmations: 0,
        };

        let first = &generate_challenges(&config, "/api/resource").unwrap()[0];
        let second = &generate_challenges(&config, "/api/resource").unwrap()[0];

        assert!(first.opaque.is_some());
        assert!(second.opaque.is_some());
        assert_ne!(first.opaque, second.opaque);
        // A distinct opaque per issue also makes the challenge id unpredictable.
        assert_ne!(first.id, second.id);
    }

    #[test]
    fn test_constant_time_eq() {
        assert!(constant_time_eq(b"hello", b"hello"));
        assert!(!constant_time_eq(b"hello", b"world"));
        assert!(!constant_time_eq(b"hello", b"hell"));
    }
}
